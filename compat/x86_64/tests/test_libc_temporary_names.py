#!/usr/bin/env python3
"""Contracts for the opt-in native x86 legacy temporary-name provider."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class X86LibcTemporaryNamesTests(unittest.TestCase):
    def test_provider_stays_opt_in_over_the_existing_allocation_client(self) -> None:
        cargo = (ROOT / "libc" / "Cargo.toml").read_text(encoding="utf-8")
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        implementation = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "temporary_names.rs"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'x86-temporary-names = ["x86-allocator-string-duplication"]',
            cargo,
        )
        self.assertIn('#[path = "temporary_names.rs"]', static_root)
        self.assertIn('#[cfg(feature = "x86-temporary-names")]', static_root)
        self.assertEqual(
            {
                line.split("fn ", 1)[1].split("(", 1)[0]
                for line in implementation.splitlines()
                if line.startswith('pub unsafe extern "C" fn ')
            },
            {"tempnam", "tmpnam"},
        )
        for required in (
            "src/stdio/tmpnam.c::tmpnam",
            "src/stdio/tempnam.c::tempnam",
            "src/temp/__randname.c::__randname",
            "MAX_ATTEMPTS: usize = 100",
            "L_TMPNAM: usize = 20",
            "PATH_MAX: usize = 4096",
            "raw_syscall::SYS_READLINK",
            "cabi_strdup",
            "errno::set_errno(ENAMETOOLONG)",
            "inherently racy",
            "does not create, open, reserve, or unlink",
        ):
            self.assertIn(required, implementation)
        for forbidden in (
            "SYS_OPEN",
            "SYS_OPENAT",
            "SYS_GETRANDOM",
            "SYS_UNLINK",
            "TMPDIR",
        ):
            self.assertNotIn(forbidden, implementation)

    def test_native_evidence_keeps_the_feature_delta_and_musl_behavior_explicit(
        self,
    ) -> None:
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_temporary_names_header_abi.sh"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_temporary_names.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_temporary_names_probe.c"
        ).read_text(encoding="utf-8")

        for required in (
            "tmpnam",
            "tempnam",
            "P_tmpdir",
            "L_tmpnam",
            "retained a mangled",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "x86-temporary-names",
            "x86-allocator-string-duplication",
            "temporary_name_members",
            "duplication_members",
            "allocator_members",
            "backend_members",
            "tmpnam",
            "tempnam",
            "pinned-musl temporary-name implementation",
            "TMPDIR",
            "sys/prctl.h",
            "assert_temporary_name_syscall_path",
            "assert_readlink_retry_path",
            "raw_syscall_helper_symbol",
            "readlink=89",
            "raw -ENOENT comparison",
            "clock_gettime=228",
            "gettid=186",
            "randomize_suffix",
        ):
            self.assertIn(required, artifact_runner)
        for required in (
            "tmpnam(caller)",
            "tmpnam((char *)0)",
            "tempnam((const char *)0, (const char *)0)",
            "FIXTURE_ENAMETOOLONG",
            "has_musl_randname_suffix",
            "path_is_absent",
            "check_readlink_failure_retry",
            "SECCOMP_RET_ERRNO",
            "FIXTURE_ELOOP",
            'tempnam("/dev/null", "x")',
            "text_length(name) != FIXTURE_PATH_MAX - 1",
            "caller[L_tmpnam - 1]",
            "free(name)",
            "crabc_x86_64_temporary_names_probe",
        ):
            self.assertIn(required, probe)


if __name__ == "__main__":
    unittest.main()
