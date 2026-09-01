#!/usr/bin/env python3
"""Contract for the opt-in x86 ``sched_rr_get_interval`` C ABI leaf."""

from __future__ import annotations

import stat
import subprocess
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
SYSCALLS = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "sched_rr_get_interval.rs"
C_HEADER_PROBE = ROOT / "compat" / "x86_64" / "sched_rr_interval_header_abi_probe.c"
CXX_HEADER_PROBE = ROOT / "compat" / "x86_64" / "sched_rr_interval_header_abi_probe.cpp"
HEADER_RUNNER = ROOT / "compat" / "x86_64" / "run_sched_rr_interval_header_abi.sh"
PROBE = ROOT / "compat" / "x86_64" / "libc_sched_rr_interval_probe.c"
START = ROOT / "compat" / "x86_64" / "libc_sched_rr_interval_start.S"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_sched_rr_interval.sh"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"
PARITY = ROOT / "compat" / "x86_64" / "parity.toml"
STATIC_EXPORTS = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"


class SchedRrIntervalTests(unittest.TestCase):
    def test_opt_in_sched_rr_interval_leaf_is_closed_and_non_promoting(self) -> None:
        for path in (
            SOURCE,
            C_HEADER_PROBE,
            CXX_HEADER_PROBE,
            HEADER_RUNNER,
            PROBE,
            START,
            RUNNER,
        ):
            self.assertTrue(path.is_file(), f"missing sched_rr_get_interval input: {path}")
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
        syscalls = SYSCALLS.read_text(encoding="utf-8")
        source = SOURCE.read_text(encoding="utf-8")
        c_header_probe = C_HEADER_PROBE.read_text(encoding="utf-8")
        cxx_header_probe = CXX_HEADER_PROBE.read_text(encoding="utf-8")
        header_runner = HEADER_RUNNER.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        start = START.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        parity = PARITY.read_text(encoding="utf-8")
        static_exports = STATIC_EXPORTS.read_text(encoding="utf-8").splitlines()

        self.assertIn("x86-sched-rr-interval = []", manifest)
        self.assertIn(
            '#[cfg(feature = "x86-sched-rr-interval")]\n'
            '#[path = "sched_rr_get_interval.rs"]\n'
            "mod sched_rr_get_interval;",
            static_root,
        )
        self.assertIn("pub(crate) const SYS_SCHED_RR_GET_INTERVAL: i64 = 148;", syscalls)
        for required in (
            "Bounded Linux/x86-64 sched_rr_get_interval C ABI boundary",
            "src/sched/sched_rr_get_interval.c::sched_rr_get_interval",
            "SYS_SCHED_RR_GET_INTERVAL",
            "raw_syscall::syscall2",
            "c_status(result)",
            "# Safety",
            'pub unsafe extern "C" fn sched_rr_get_interval',
        ):
            self.assertIn(required, source)
        for forbidden in ("alloc::", "pthread_", "sched_set", "sched_getparam"):
            self.assertNotIn(forbidden, source)

        for header_probe in (c_header_probe, cxx_header_probe):
            self.assertIn("sched_rr_get_interval", header_probe)
            self.assertIn("timespec", header_probe)
            self.assertIn("sizeof(pid_t) == 4", header_probe)
            self.assertIn("sizeof(struct timespec) == 16", header_probe)
        for required in (
            "for profile in strict posix xopen gnu",
            "unmangled sched_rr_get_interval",
            "project trace omitted",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "sched_rr_get_interval(0, &self.value)",
            "INT_MAX",
            "ESRCH",
            "ERANGE",
            "SYS_sched_rr_get_interval == 148",
            "sizeof(struct timespec) == 16",
            "trailing_is_unchanged",
        ):
            self.assertIn(required, probe)
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertNotIn("arch_prctl", start)

        for required in (
            "x86-sched-rr-interval",
            "assert_feature_delta",
            "run_sched_rr_interval_header_abi.sh",
            "syscall 148",
            "-nostdlib -static",
            "candidate errno does not use direct initial TLS",
            "scheduler policy mutation",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)
        self.assertNotIn("sched_rr_get_interval", static_exports)
        for required in (
            "run_libc_sched_rr_interval_probe()",
            "run_libc_sched_rr_interval.sh",
            "libc-sched-rr-interval)",
            "libc-sched-rr-interval takes no arguments",
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
            if record["id"] == "static-c-sched-rr-interval"
        )
        self.assertNotIn("capabilities", artifact)
        self.assertIn("x86-sched-rr-interval", artifact["description"])
        self.assertIn("does not select scheduler policy mutation", artifact["description"])
        self.assertIn(
            "libc/src/c_abi/x86_64/sched_rr_get_interval.rs",
            artifact["source_owners"],
        )
        self.assertEqual(1, len(artifact["native_evidence"]))
        evidence = artifact["native_evidence"][0]
        self.assertEqual("verified", evidence["state"])
        self.assertEqual(
            "./scripts/dev-x86_64.sh libc-sched-rr-interval", evidence["command"]
        )
        for boundary in (
            "exactly sched_rr_get_interval",
            "does not select scheduler policy mutation",
            "public x86 support",
        ):
            self.assertIn(boundary, evidence["scope"])


if __name__ == "__main__":
    unittest.main()
