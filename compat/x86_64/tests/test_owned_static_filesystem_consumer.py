#!/usr/bin/env python3
"""Contracts for the owned aggregate's installed directory consumer."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class OwnedStaticFilesystemConsumerTests(unittest.TestCase):
    def test_owned_aggregate_inherits_only_the_ready_directory_features(self) -> None:
        manifest = (ROOT / "libc" / "Cargo.toml").read_text(encoding="utf-8")

        aggregate = manifest.split("x86-owned-static-runtime = [", 1)[1].split("]", 1)[0]
        self.assertIn('"x86-scandir",', aggregate)
        self.assertIn('"x86-filesystem-traversal",', aggregate)
        self.assertNotIn("x86-temporary-names", aggregate)
        self.assertNotIn("x86-file-handles", aggregate)
        self.assertIn('x86-scandir = ["x86-allocator-runtime"]', manifest)
        self.assertIn("x86-filesystem-traversal = []", manifest)

    def test_owned_runtime_preserves_scandir_and_nftw_cancellation_source_forms(self) -> None:
        directory = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "directory_streams.rs"
        ).read_text(encoding="utf-8")
        traversal = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "filesystem_traversal.rs"
        ).read_text(encoding="utf-8")

        self.assertNotIn("owned_static_scandir_cancellation_point", directory)
        self.assertNotIn("pthread_testcancel", directory)
        self.assertIn("has no cancellation-state wrapper", directory)

        self.assertIn('#[cfg(feature = "x86-owned-static-runtime")]', traversal)
        self.assertIn("unsafe fn owned_static_nftw_cancellation_guard", traversal)
        self.assertIn("pthread_setcancelstate(", traversal)
        self.assertIn("PTHREAD_CANCEL_DISABLE", traversal)
        self.assertIn("src/misc/nftw.c", traversal)
        self.assertIn("disable/walk/restore", traversal)
        self.assertNotIn("owned_static_traversal_cancellation_point", traversal)
        self.assertNotIn("pthread_testcancel", traversal)
        for entry in ("nftw", "ftw"):
            signature = f'pub unsafe extern "C" fn {entry}('
            entry_body = traversal.split(signature, 1)[1]
            self.assertIn("owned_static_nftw_cancellation_guard", entry_body)

    def test_reusable_runner_consumes_a_preinstalled_sysroot_without_the_root_gate(self) -> None:
        probe = (
            ROOT / "compat" / "x86_64" / "owned_static_filesystem_consumer.c"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "compat" / "x86_64" / "run_owned_static_filesystem_consumer.sh"
        ).read_text(encoding="utf-8")

        for required in (
            "scandir(argv[1], &entries, keep_visible, alphasort)",
            "ftw(argv[1], visit_ftw, 4)",
            "nftw(argv[1], visit, 4, FTW_PHYS)",
            "free(entries[index])",
            "ftw_directories != 2",
            "traversal.directories != 2",
            "traversal.files != 2",
            "run_cancellation_round(argv[1], CANCELLATION_NFTW)",
            "run_cancellation_round(argv[1], CANCELLATION_FTW)",
            "pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_state)",
            "pthread_testcancel();",
            "result != PTHREAD_CANCELED",
        ):
            self.assertIn(required, probe)
        for required in (
            "usage: %s <installed-owned-static-sysroot>",
            "readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc",
            '"$sysroot/bin/crabc-cc" "$mode"',
            "--link-receipt link.receipt.json",
            "installed sysroot lacks",
            "runtime allowlist or exact application-object receipt drifted",
            "audit_linker_trace(",
            "application_paths=(application,)",
            "run_installed_mode -static et-exec",
            "run_installed_mode -static-pie static-pie",
            "Requesting program interpreter|INTERP",
            "for symbol in scandir ftw nftw pthread_cancel pthread_setcancelstate pthread_testcancel; do",
            "timeout 30 env -i",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("build_x86_64_owned_sysroot.py", runner)
        self.assertNotIn("run_owned_static_sysroot.sh", runner)
        self.assertTrue((ROOT / "compat" / "x86_64" / "run_owned_static_filesystem_consumer.sh").stat().st_mode & 0o111)


if __name__ == "__main__":
    unittest.main()
