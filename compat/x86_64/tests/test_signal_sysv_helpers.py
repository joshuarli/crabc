"""Closed source contract for the private x86 SysV signal-helper artifact."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class X86SignalSysvHelpersTests(unittest.TestCase):
    def test_module_keeps_the_four_helper_closure_below_signal_promotion(self) -> None:
        source_path = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "signal_sysv_helpers.rs"
        )
        source = source_path.read_text(encoding="utf-8")

        for required in (
            "pinned musl 1.2.6",
            "src/signal/sighold.c",
            "src/signal/sigignore.c",
            "src/signal/sigrelse.c",
            "src/signal/sigset.c",
            "raw_syscall::SYS_RT_SIGACTION",
            "raw_syscall::SYS_RT_SIGPROCMASK",
            "signal_foundation::pack_public_action",
            "does not select `process.signal`",
            "pthread",
            "cancellation",
        ):
            self.assertIn(required, source)

        exports = set(
            re.findall(
                r'(?m)^pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
                source,
            )
        )
        self.assertEqual({"sighold", "sigignore", "sigrelse", "sigset"}, exports)
        for forbidden in (
            "fn sigaction(",
            "fn signal(",
            "fn sigprocmask(",
            "fn pthread_sigmask(",
            "fn sigsuspend(",
            "crabc_core",
            "crabc_mimalloc",
        ):
            self.assertNotIn(forbidden, source)

    def test_artifact_evidence_keeps_the_header_and_runtime_boundaries_separate(
        self,
    ) -> None:
        paths = {
            "c_header": ROOT
            / "compat"
            / "x86_64"
            / "signal_sysv_helpers_header_abi_probe.c",
            "cxx_header": ROOT
            / "compat"
            / "x86_64"
            / "signal_sysv_helpers_header_abi_probe.cpp",
            "header_runner": ROOT
            / "compat"
            / "x86_64"
            / "run_signal_sysv_helpers_header_abi.sh",
            "probe": ROOT
            / "compat"
            / "x86_64"
            / "libc_signal_sysv_helpers_probe.c",
            "start": ROOT
            / "compat"
            / "x86_64"
            / "libc_signal_sysv_helpers_start.S",
            "runtime_runner": ROOT
            / "compat"
            / "x86_64"
            / "run_libc_signal_sysv_helpers.sh",
        }
        for path in paths.values():
            self.assertTrue(path.is_file(), f"missing SysV-helper evidence input: {path}")
        self.assertTrue(paths["header_runner"].stat().st_mode & 0o111)
        self.assertTrue(paths["runtime_runner"].stat().st_mode & 0o111)

        c_header = paths["c_header"].read_text(encoding="utf-8")
        cxx_header = paths["cxx_header"].read_text(encoding="utf-8")
        header_runner = paths["header_runner"].read_text(encoding="utf-8")
        probe = paths["probe"].read_text(encoding="utf-8")
        start = paths["start"].read_text(encoding="utf-8")
        runtime_runner = paths["runtime_runner"].read_text(encoding="utf-8")

        for header in (c_header, cxx_header):
            for symbol in ("sighold", "sigignore", "sigrelse", "sigset"):
                self.assertIn(symbol, header)
            self.assertIn("CRABC_EXPECT_SYSV_SIGNAL_HELPERS", header)
            self.assertIn("CRABC_REQUIRE_SYSV_SIGNAL_HELPERS_HIDDEN", header)
        self.assertIn('extern "C"', cxx_header)
        for required in (
            "XOPEN=700",
            "XOPEN=800",
            "post-POSIX.1-2024",
            "CRABC_EXPECT_SYSV_SIGNAL_HELPERS",
            "CRABC_REQUIRE_SYSV_SIGNAL_HELPERS_HIDDEN",
            "retained a mangled",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "direct_sighold",
            "direct_sigignore",
            "direct_sigrelse",
            "direct_sigset",
            "E2BIG",
            "SIG_HOLD",
            "CRABC_SIGNAL_SYSV_HELPERS_FREESTANDING",
            "raw_sigaction",
            "raw_sigprocmask",
        ):
            self.assertIn(required, probe)
        for required in (
            "__crabc_x86_static_tls_bootstrap",
            "crabc_x86_64_signal_sysv_helpers_probe",
        ):
            self.assertIn(required, start)
        for required in (
            "FEATURE=x86-signal-sysv-helpers",
            "EXPECTED_ADDITIONS=(sighold sigignore sigrelse sigset)",
            "run_signal_sysv_helpers_header_abi.sh",
            "unfeatured selected-static C ABI export surface drifted",
            "-nostdlib -static",
            "--features \"$FEATURE\"",
            "candidate unexpectedly pulls",
            "does not select process.signal",
        ):
            self.assertIn(required, runtime_runner)
        self.assertNotIn("--whole-archive", runtime_runner)


if __name__ == "__main__":
    unittest.main()
