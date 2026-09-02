#!/usr/bin/env python3
"""Contract for the opt-in x86 ``h_errno`` static-TLS ABI artifact."""

from __future__ import annotations

import stat
import subprocess
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "h_errno.rs"
RUNTIME = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "resolver_runtime.rs"
C_HEADER_PROBE = ROOT / "compat" / "x86_64" / "h_errno_header_abi_probe.c"
CXX_HEADER_PROBE = ROOT / "compat" / "x86_64" / "h_errno_header_abi_probe.cpp"
HEADER_RUNNER = ROOT / "compat" / "x86_64" / "run_h_errno_header_abi.sh"
PROBE = ROOT / "compat" / "x86_64" / "libc_h_errno_probe.c"
START = ROOT / "compat" / "x86_64" / "libc_h_errno_start.S"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_h_errno.sh"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"
PARITY = ROOT / "compat" / "x86_64" / "parity.toml"
STATIC_EXPORTS = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"


class HErrnoTests(unittest.TestCase):
    def test_opt_in_h_errno_owner_keeps_resolver_runtime_separate(self) -> None:
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
                self.fail(f"missing h_errno input: {path}")

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
        runtime = RUNTIME.read_text(encoding="utf-8")
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

        self.assertIn("x86-h-errno = []", manifest)
        self.assertIn(
            'x86-resolver-runtime = ["dep:crabc-core", "x86-h-errno"]', manifest
        )
        self.assertIn(
            '#[cfg(feature = "x86-h-errno")]\n#[path = "h_errno.rs"]\nmod h_errno;',
            static_root,
        )
        for required in (
            "Pinned musl 1.2.6",
            "src/network/h_errno.c",
            "h_errno.lo",
            "pub static mut h_errno: c_int = 0;",
            "#[thread_local]",
            "static_tls::is_initial_thread_pointer(thread_pointer)",
            "pub extern \"C\" fn __h_errno_location() -> *mut c_int",
            "selected pthread workers",
            "foreign-thread",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertNotIn("pub static mut h_errno", runtime)
        self.assertNotIn("fn __h_errno_location", runtime)
        self.assertIn("h_errno::set(value)", runtime)
        self.assertIn("h_errno::current()", runtime)

        for header_probe_path, header_probe in (
            (C_HEADER_PROBE, c_header_probe),
            (CXX_HEADER_PROBE, cxx_header_probe),
        ):
            for required in (
                "#include <netdb.h>",
                "#ifndef h_errno",
                "h_errno_location_signature",
                "__h_errno_location",
            ):
                with self.subTest(header_probe=header_probe_path.name, required=required):
                    self.assertIn(required, header_probe)
        for required in (
            "c11-gnu",
            "c11-bsd",
            "cxx17-gnu",
            "cxx17-strict",
            "h_errno macro",
            "retained a mangled",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "crabc_link_visible_h_errno",
            "check_h_errno_worker",
            "pthread_create",
            "pthread_join",
            "worker_location == context->main_location",
            "h_errno != NO_RECOVERY",
        ):
            self.assertIn(required, probe)
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertIn("crabc_x86_64_h_errno_probe", start)

        for required in (
            "x86-h-errno",
            "assert_feature_delta",
            "__h_errno_location",
            "h_errno",
            "h_errno.lo",
            "R_X86_64_TPOFF",
            "resolver_runtime",
            "--features x86-resolver-runtime",
            "-nostdlib -static",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertFalse(static_exports & {"h_errno", "__h_errno_location"})
        for required in (
            "h-errno-header-abi)",
            "libc-h-errno)",
            "run_h_errno_header_abi.sh",
            "run_libc_h_errno.sh",
        ):
            self.assertIn(required, dispatcher)

        resolver = next(family for family in ledger["family"] if family["id"] == "libc.resolver")
        self.assertEqual("planned", resolver["status"])
        artifact = next(
            record
            for record in resolver["verified_artifact"]
            if record["id"] == "static-c-h-errno"
        )
        self.assertNotIn("capabilities", artifact)
        self.assertIn("h_errno", artifact["description"])
        self.assertIn("does not complete", artifact["description"])
        self.assertIn("process.globals", artifact["description"])
        self.assertIn("libc/src/c_abi/x86_64/h_errno.rs", artifact["source_owners"])
        self.assertEqual(1, len(artifact["native_evidence"]))
        evidence = artifact["native_evidence"][0]
        self.assertEqual("verified", evidence["state"])
        self.assertEqual("./scripts/dev-x86_64.sh libc-h-errno", evidence["command"])
        self.assertTrue(
            "no resolver configuration" in evidence["scope"]
            or "rejects resolver configuration" in evidence["scope"]
        )
        for boundary in ("does not complete", "public x86 support"):
            self.assertIn(boundary, evidence["scope"])

        feature = next(
            record for record in ledger["feature_archive"] if record["id"] == "x86-h-errno"
        )
        self.assertEqual("verified", feature["state"])
        self.assertEqual([], feature["baseline_features"])
        self.assertEqual(["__h_errno_location"], feature["additive_callables"])
        resolver_feature = next(
            record
            for record in ledger["feature_archive"]
            if record["id"] == "x86-resolver-runtime"
        )
        self.assertEqual(["x86-h-errno"], resolver_feature["baseline_features"])
        self.assertNotIn("__h_errno_location", resolver_feature["additive_callables"])


if __name__ == "__main__":
    unittest.main()
