#!/usr/bin/env python3
"""Contract for the opt-in x86 ``sethostent``/``setnetent`` C ABI pair."""

from __future__ import annotations

import stat
import subprocess
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sethostent.rs"
C_HEADER_PROBE = ROOT / "compat" / "x86_64" / "endhostent_header_abi_probe.c"
CXX_HEADER_PROBE = ROOT / "compat" / "x86_64" / "endhostent_header_abi_probe.cpp"
HEADER_RUNNER = ROOT / "compat" / "x86_64" / "run_endhostent_header_abi.sh"
PROBE = ROOT / "compat" / "x86_64" / "libc_sethostent_probe.c"
START = ROOT / "compat" / "x86_64" / "libc_sethostent_start.S"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_sethostent.sh"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"
PARITY = ROOT / "compat" / "x86_64" / "parity.toml"
STATIC_EXPORTS = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"


class SetHostEntTests(unittest.TestCase):
    def test_opt_in_setent_pair_is_source_split_and_stateless(self) -> None:
        for path in (
            SOURCE,
            C_HEADER_PROBE,
            CXX_HEADER_PROBE,
            HEADER_RUNNER,
            PROBE,
            START,
            RUNNER,
        ):
            self.assertTrue(path.is_file(), f"missing sethostent input: {path}")
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
        c_header_probe = C_HEADER_PROBE.read_text(encoding="utf-8")
        cxx_header_probe = CXX_HEADER_PROBE.read_text(encoding="utf-8")
        header_runner = HEADER_RUNNER.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        start = START.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        static_exports = STATIC_EXPORTS.read_text(encoding="utf-8").splitlines()
        ledger = tomllib.loads(PARITY.read_text(encoding="utf-8"))

        self.assertIn("x86-netdb-setent = []", manifest)
        self.assertIn(
            '#[cfg(feature = "x86-netdb-setent")]\n#[path = "sethostent.rs"]\nmod sethostent;',
            static_root,
        )
        for required in (
            "Pinned musl 1.2.6",
            "src/network/ent.c::sethostent",
            "weak_alias(sethostent, setnetent)",
            "System V AMD64 ABI",
            ".weak setnetent",
            ".set setnetent, sethostent",
            'pub extern "C" fn sethostent(_stayopen: c_int)',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "static mut",
            "errno::",
            "static_tls::",
            "raw_syscall",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, source)

        for header_probe in (c_header_probe, cxx_header_probe):
            for required in (
                "sethostent_signature",
                "sethostent_function",
                "setnetent_function",
            ):
                self.assertIn(required, header_probe)
        for required in (
            "sethostent",
            "setnetent",
            "unconditional",
            "retained a mangled $symbol reference",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "INT_MIN",
            "INT_MAX",
            "sethostent_signature",
            "host_function != net_function",
            "CRABC_SETHOSTENT_OVERRIDE",
            "CRABC_SETHOSTENT_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("crabc_x86_64_sethostent_probe", start)
        self.assertIn("mov $60, %eax", start)

        for required in (
            "x86-netdb-setent",
            "assert_feature_delta",
            "sethostent\\nsetnetent\\n",
            "run_endhostent_header_abi.sh",
            "ent.lo",
            "candidate setnetent is not the same-address weak sethostent alias",
            "caller strong setnetent did not override the archive weak binding",
            "sethostent code section selects a call, TLS, syscall, or an unowned runtime",
            "-nostdlib -static",
            "--gc-sections",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertNotIn("sethostent", static_exports)
        self.assertNotIn("setnetent", static_exports)
        for required in (
            "libc-sethostent)",
            "libc-sethostent takes no arguments",
            "run_in_container bash /workspace/compat/x86_64/run_libc_sethostent.sh",
        ):
            self.assertIn(required, dispatcher)

        family = next(
            family for family in ledger["family"] if family["id"] == "libc.c-abi-compat"
        )
        self.assertEqual("planned", family["status"])
        artifact = next(
            record
            for record in family["verified_artifact"]
            if record["id"] == "static-c-sethostent"
        )
        self.assertNotIn("capabilities", artifact)
        self.assertIn("x86-netdb-setent", artifact["description"])
        self.assertIn("does not complete", artifact["description"])
        self.assertIn("libc/src/c_abi/x86_64/sethostent.rs", artifact["source_owners"])
        self.assertIn("scripts/check_structure.py", artifact["source_owners"])
        self.assertEqual(1, len(artifact["native_evidence"]))
        evidence = artifact["native_evidence"][0]
        self.assertEqual("verified", evidence["state"])
        self.assertEqual("./scripts/dev-x86_64.sh libc-sethostent", evidence["command"])
        for boundary in (
            "exactly sethostent/setnetent",
            "does not complete",
            "public x86 support",
        ):
            self.assertIn(boundary, evidence["scope"])


if __name__ == "__main__":
    unittest.main()
