#!/usr/bin/env python3
"""Source contracts for the standalone inert-DES feature profile."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
OWNER = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "legacy_des_compat.rs"
PROBE = ROOT / "compat" / "x86_64" / "libc_legacy_des_compat_probe.c"
START = ROOT / "compat" / "x86_64" / "libc_legacy_des_compat_start.S"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_legacy_des_compat.sh"


class X86LegacyDesCompatTests(unittest.TestCase):
    def test_narrow_feature_owns_only_the_inert_des_spelling_pair(self) -> None:
        manifest = MANIFEST.read_text(encoding="utf-8")
        static_root = STATIC_ROOT.read_text(encoding="utf-8")
        owner = OWNER.read_text(encoding="utf-8")

        self.assertIn("x86-legacy-des-compat = []", manifest)
        self.assertIn(
            'x86-legacy-misc = ["x86-legacy-des-compat"]', manifest
        )
        self.assertIn('"x86-legacy-misc",', manifest)
        self.assertIn(
            '#[cfg(feature = "x86-legacy-des-compat")]\n'
            '#[path = "legacy_des_compat.rs"]\n'
            'mod legacy_des_compat;',
            static_root,
        )
        for required in (
            "x86-legacy-des-compat",
            "inert-DES",
            "does not alter errno",
            'pub extern "C" fn setkey',
            'pub extern "C" fn encrypt',
        ):
            self.assertIn(required, owner)
        self.assertNotIn('pub unsafe extern "C" fn', owner)

    def test_direct_native_proof_seals_the_feature_surface_and_invalid_pointers(self) -> None:
        probe = PROBE.read_text(encoding="utf-8")
        start = START.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        for required in (
            "setkey(NULL)",
            "encrypt(NULL, -1)",
            "(const char *)(uintptr_t)1",
            "(char *)(uintptr_t)1",
            "ERANGE",
            "EILSEQ",
            "CRABC_LEGACY_DES_COMPAT_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        for required in (
            "FEATURE=x86-legacy-des-compat",
            "FEATURE_EXPORTS=(encrypt setkey)",
            "default archive unexpectedly exposes opt-in",
            "narrow feature widened the archive",
            "collect_global_bindings",
            "narrow feature changed the full global binding surface",
            "both-feature closure changed the full global binding surface",
            "assert_provider_counts",
            "providers default/narrow/composite",
            '"${#both_encrypt_members[@]}" 0 1 1',
            '"${#both_fmtmsg_members[@]}" 0 0 1',
            "fmtmsg",
            "both-feature closure",
            "ar p",
            "candidate link map did not take the encrypt defining archive member",
            "candidate link map did not take the setkey defining archive member",
            "checkout_local_tmpdir",
            "readlink -f",
            "retained failure evidence",
            "candidate errno does not use direct initial TLS",
            "inert DES compatibility functions select a local cipher",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("names must share exactly one target-local archive owner", runner)
        self.assertNotIn("must retain a distinct fmtmsg owner", runner)
        self.assertNotIn("owner export surface drifted", runner)


if __name__ == "__main__":
    unittest.main()
