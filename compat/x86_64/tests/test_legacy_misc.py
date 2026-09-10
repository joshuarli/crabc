#!/usr/bin/env python3
"""Focused source contracts for the opt-in x86 frozen legacy.misc slice."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
LIBC_MANIFEST = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
OWNER = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "legacy_misc.rs"
DES_OWNER = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "legacy_des_compat.rs"
HEADER_C = ROOT / "compat" / "x86_64" / "legacy_misc_header_abi_probe.c"
HEADER_CXX = ROOT / "compat" / "x86_64" / "legacy_misc_header_abi_probe.cpp"
HEADER_RUNNER = ROOT / "compat" / "x86_64" / "run_legacy_misc_header_abi.sh"
PROBE = ROOT / "compat" / "x86_64" / "libc_legacy_misc_probe.c"
START = ROOT / "compat" / "x86_64" / "libc_legacy_misc_start.S"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_legacy_misc.sh"


class X86LegacyMiscTests(unittest.TestCase):
    def test_feature_is_opt_in_and_the_default_root_stays_narrow(self) -> None:
        manifest = LIBC_MANIFEST.read_text(encoding="utf-8")
        root = STATIC_ROOT.read_text(encoding="utf-8")

        self.assertIn(
            'x86-legacy-misc = ["x86-legacy-des-compat"]', manifest
        )
        self.assertIn(
            '#[cfg(all(feature = "x86-legacy-misc", '
            'not(feature = "x86-owned-static-runtime")))]\n'
            '#[path = "legacy_misc.rs"]\nmod legacy_misc;', root,
        )
        self.assertIn(
            '#[cfg(feature = "x86-legacy-des-compat")]\n'
            '#[path = "legacy_des_compat.rs"]\n'
            'mod legacy_des_compat;',
            root,
        )
        self.assertIn("default export", root)

    def test_fmtmsg_and_inert_des_keep_distinct_owners(self) -> None:
        source = OWNER.read_text(encoding="utf-8")
        des_source = DES_OWNER.read_text(encoding="utf-8")

        for required in (
            "src/misc/fmtmsg.c::fmtmsg",
            "Public domain fmtmsg(); Written by Isaac",
            "Dunham, 2014",
            "src/legacy/encrypt.c::{setkey,encrypt}",
            'pub unsafe extern "C" fn fmtmsg',
            "MSGVERB",
            "MM_NOMSG",
            "MM_NOCON",
            "MM_NOTOK",
            "retry-on-short-write",
        ):
            self.assertIn(required, source)

        self.assertNotIn('pub extern "C" fn setkey', source)
        self.assertNotIn('pub extern "C" fn encrypt', source)

        for required in (
            "src/legacy/encrypt.c::setkey",
            "src/legacy/encrypt.c::encrypt",
            "x86-owned-static-runtime",
            "x86-legacy-misc",
            "inert-DES",
            "intentional divergence",
            "no-hand-rolled-cryptography",
            "use core::ffi::{c_char, c_int};",
            'pub extern "C" fn setkey',
            'pub extern "C" fn encrypt',
            "neither read nor write",
            "does not alter errno",
        ):
            self.assertIn(required, des_source)

        # `legacy_formatting_exports.rs` also owns strfmon; the x86 aggregate
        # must not pull that locale/formatter surface in merely to gain fmtmsg.
        self.assertNotIn("strfmon", source)
        self.assertNotIn("sha_crypt", source)
        self.assertNotIn("mimalloc", source)
        self.assertNotIn("sha_crypt", des_source)
        self.assertNotIn("mimalloc", des_source)

    def test_header_matrix_preserves_the_three_profile_partitions(self) -> None:
        runner = HEADER_RUNNER.read_text(encoding="utf-8")
        probes = (
            HEADER_C.read_text(encoding="utf-8"),
            HEADER_CXX.read_text(encoding="utf-8"),
        )

        for probe in probes:
            for required in (
                "fmtmsg_signature",
                "encrypt_signature",
                "setkey_signature",
                "get_nprocs_signature",
                "get_pages_signature",
                "issetugid_signature",
                "CRABC_LEGACY_MISC_EXPECT_BASE",
                "CRABC_LEGACY_MISC_EXPECT_XOPEN",
                "CRABC_LEGACY_MISC_EXPECT_GNU_BSD",
                "CRABC_LEGACY_MISC_REQUIRE_XOPEN_HIDDEN",
                "CRABC_LEGACY_MISC_REQUIRE_ISSETUGID_HIDDEN",
                "MM_PRINT == 256",
                "MM_CONSOLE == 512",
                "MM_NOTOK == -1",
                "MM_NOMSG == 1",
                "MM_NOCON == 4",
            ):
                self.assertIn(required, probe)

        for required in (
            "compile_visible_profile strict base",
            "compile_visible_profile posix base",
            "compile_visible_profile xopen xopen",
            "compile_visible_profile gnu gnu-bsd",
            "compile_visible_profile bsd gnu-bsd",
            "CRABC_LEGACY_MISC_REQUIRE_XOPEN_HIDDEN",
            "CRABC_LEGACY_MISC_REQUIRE_ISSETUGID_HIDDEN",
            "C++ probe lacks C linkage",
            "retained a mangled",
            "-nostdinc",
            "-nostdinc++",
        ):
            self.assertIn(required, runner)

    def test_behavior_runner_ratcheted_the_nonpromotion_and_static_closure(self) -> None:
        probe = PROBE.read_text(encoding="utf-8")
        start = START.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        for required in (
            "capture_print",
            "not-a-component",
            "check_closed_stderr_error",
            "EBADF",
            "check_short_write_error",
            "EAGAIN",
            "check_console_path",
            "check_des_boundary",
            "check_des_inert_arguments",
            "ERANGE",
            "setkey(NULL)",
            "encrypt(NULL, -1)",
            "CRABC_LEGACY_MISC_CANDIDATE",
            "check_retained_observations",
            "get_nprocs_conf",
            "get_avphys_pages",
            "issetugid",
        ):
            self.assertIn(required, probe)
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertIn("__libc_start_main", start)
        for required in (
            "FEATURE=x86-legacy-misc",
            "FEATURE_EXPORTS=(encrypt fmtmsg setkey)",
            "x86-owned-static-runtime",
            "run_legacy_misc_header_abi.sh",
            "run_libc_system_information.sh",
            "run_libc_issetugid.sh",
            "unfeatured selected-static C ABI export surface drifted",
            "collect_global_bindings",
            "narrow inert-DES changed more than encrypt/setkey",
            "narrow inert-DES changed the full global binding surface",
            "composite legacy.misc changed more than fmtmsg beyond narrow inert-DES",
            "composite legacy.misc changed the full global binding surface",
            "assert_provider_counts",
            "providers default/narrow/composite",
            '"${#encrypt_members[@]}" 0 1 1',
            '"${#fmtmsg_members[@]}" 0 0 1',
            "ar p",
            "inert DES compatibility functions select a local cipher",
            "candidate link map did not take the fmtmsg defining archive member",
            "candidate link map did not take the encrypt defining archive member",
            "candidate link map did not take the setkey defining archive member",
            "checkout_local_tmpdir",
            "readlink -f",
            "retained failure evidence",
            "candidate selected a pinned-musl fmtmsg or DES implementation",
            "candidate retains an unresolved symbol",
            "candidate selects a dynamic runtime",
            "candidate retains a dynamic TLS model",
            "not a full legacy runtime",
            "public support claim",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("owner export surface drifted", runner)
        self.assertNotIn("names must have one target-local archive owner", runner)
        self.assertNotIn("must retain a distinct fmtmsg owner", runner)


if __name__ == "__main__":
    unittest.main()
