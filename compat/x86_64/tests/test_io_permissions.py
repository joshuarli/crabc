#!/usr/bin/env python3
"""Contract for the opt-in x86 ``iopl``/``ioperm`` negative-path slice."""

from __future__ import annotations

import stat
import subprocess
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "io_permissions.rs"
PROBE = ROOT / "compat" / "x86_64" / "libc_io_permissions_probe.c"
START = ROOT / "compat" / "x86_64" / "libc_io_permissions_start.S"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_io_permissions.sh"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"
PARITY = ROOT / "compat" / "x86_64" / "parity.toml"
STATIC_EXPORTS = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"


class IoPermissionsTests(unittest.TestCase):
    def test_opt_in_iopl_ioperm_slice_is_bounded_and_non_privileged(self) -> None:
        for path in (SOURCE, PROBE, START, RUNNER):
            self.assertTrue(path.is_file(), f"missing iopl/ioperm input: {path}")
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
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
        probe = PROBE.read_text(encoding="utf-8")
        start = START.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        parity = PARITY.read_text(encoding="utf-8")
        static_exports = STATIC_EXPORTS.read_text(encoding="utf-8").splitlines()

        self.assertIn("x86-io-permissions = []", manifest)
        self.assertIn(
            '#[cfg(feature = "x86-io-permissions")]\n'
            '#[path = "io_permissions.rs"]\n'
            "mod io_permissions;",
            static_root,
        )
        for required in (
            "Bounded Linux/x86-64 iopl/ioperm C ABI boundary",
            "src/linux/iopl.c::iopl",
            "src/linux/ioperm.c::ioperm",
            "SYS_IOPL",
            "SYS_IOPERM",
            "c_status(result)",
            "when its authority check comes first",
            'pub unsafe extern "C" fn iopl',
            'pub unsafe extern "C" fn ioperm',
            "# Safety",
        ):
            self.assertIn(required, source)
        for forbidden in ("inb", "outb", "insb", "outsb", "alloc::", "pthread_"):
            self.assertNotIn(forbidden, source)

        for required in (
            "observe_iopl_invalid(-1)",
            "observe_iopl_invalid(4)",
            "observe_ioperm_invalid(65536UL, 1UL, 0)",
            "observe_ioperm_invalid(0UL, 65537UL, 0)",
            "EINVAL",
            "EPERM",
            "SYS_iopl == 172",
            "SYS_ioperm == 173",
        ):
            self.assertIn(required, probe)
        self.assertNotIn("iopl(0)", probe)
        self.assertNotIn("ioperm(0UL, 1UL, 1)", probe)
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertNotIn("arch_prctl", start)
        self.assertNotIn("inb", start)
        self.assertNotIn("outb", start)

        for required in (
            "--features \"$FEATURE\"",
            "assert_feature_delta",
            "ioperm\\niopl",
            "run_sys_io_header_abi.sh",
            "iopl) syscall_immediate",
            "ioperm) syscall_immediate",
            "does not issue its Linux syscall",
            "unexpectedly contains a port-I/O instruction",
            "no port-I/O execution",
            "capture_invalid_probe_status",
            "errno fingerprint differs from pinned musl",
            "-nostdlib -static",
            "candidate selects a dynamic runtime",
            "candidate errno does not use direct initial TLS",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertNotIn("iopl", static_exports)
        self.assertNotIn("ioperm", static_exports)
        for required in (
            'id = "static-c-iopl-ioperm"',
            'command = "./scripts/dev-x86_64.sh libc-io-permissions"',
            "x86-io-permissions",
            "neither enables I/O permissions nor executes port I/O",
        ):
            self.assertIn(required, parity)
        for required in (
            "run_libc_io_permissions_probe()",
            "run_libc_io_permissions.sh",
            "libc-io-permissions)",
            "libc-io-permissions takes no arguments",
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
            if record["id"] == "static-c-iopl-ioperm"
        )
        self.assertNotIn("capabilities", artifact)
        self.assertIn("x86-io-permissions", artifact["description"])
        self.assertIn(
            "compares the observed EINVAL-versus-EPERM fingerprint",
            artifact["description"],
        )
        self.assertIn(
            "libc/src/c_abi/x86_64/io_permissions.rs", artifact["source_owners"]
        )
        self.assertIn(
            "compat/x86_64/run_libc_io_permissions.sh", artifact["source_owners"]
        )
        self.assertEqual(1, len(artifact["native_evidence"]))
        evidence = artifact["native_evidence"][0]
        self.assertEqual("verified", evidence["state"])
        self.assertEqual(
            "./scripts/dev-x86_64.sh libc-io-permissions", evidence["command"]
        )
        for boundary in (
            "exactly iopl/ioperm",
            "neither enables I/O permissions nor executes port I/O",
            "does not select kernel-administration capability",
            "family completion",
            "public support",
        ):
            self.assertIn(boundary, evidence["scope"])


if __name__ == "__main__":
    unittest.main()
