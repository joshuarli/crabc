#!/usr/bin/env python3
"""Composition and same-object contracts for installed POSIX filesystem APIs."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CARGO = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
COMPAT = ROOT / "libc" / "src" / "compat_exports.rs"
DIRECTORY = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "directory_streams.rs"
TRAVERSAL = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "filesystem_traversal.rs"
HANDLES = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "file_handles.rs"
TEMPORARY_NAMES = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "temporary_names.rs"
OWNED_FILESYSTEM = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "owned_filesystem_mechanisms.rs"
QUALIFICATION = ROOT / "compat" / "x86_64" / "owned_dynamic_qualification.py"
RUNNER = ROOT / "compat" / "x86_64" / "run_owned_posix_filesystem.sh"
PROBE = ROOT / "compat" / "x86_64" / "owned_posix_filesystem_probe.c"


class OwnedPosixFilesystemTests(unittest.TestCase):
    def test_owned_runtime_selects_existing_file_handle_and_temporary_name_leaves(self) -> None:
        manifest = CARGO.read_text(encoding="utf-8")
        aggregate = manifest.split("x86-owned-static-runtime = [", 1)[1].split("]", 1)[0]
        self.assertIn('"x86-file-handles",', aggregate)
        self.assertIn('"x86-temporary-names",', aggregate)

        root = STATIC_ROOT.read_text(encoding="utf-8")
        self.assertIn('#[cfg(feature = "x86-file-handles")]\n#[path = "file_handles.rs"]', root)
        self.assertIn('#[cfg(feature = "x86-temporary-names")]\n#[path = "temporary_names.rs"]', root)

    def test_source_owners_retain_the_pinned_musl_boundaries(self) -> None:
        compat = COMPAT.read_text(encoding="utf-8")
        for name in ("__xstat", "__lxstat", "__fxstat", "__fxstatat"):
            self.assertIn(f"fn {name}(", compat)

        directory = DIRECTORY.read_text(encoding="utf-8")
        for name in ("readdir_r", "telldir", "alphasort", "versionsort", "scandir"):
            self.assertIn(f"fn {name}(", directory)
        self.assertIn("src/dirent/scandir.c", directory)

        traversal = TRAVERSAL.read_text(encoding="utf-8")
        for source in ("src/legacy/ftw.c", "src/misc/nftw.c", "disable/walk/restore"):
            self.assertIn(source, traversal)
        self.assertIn("pthread_setcancelstate", traversal)

        handles = HANDLES.read_text(encoding="utf-8")
        for source in ("src/linux/name_to_handle_at.c", "src/linux/open_by_handle_at.c"):
            self.assertIn(source, handles)
        self.assertIn("caller-owned", handles)

        temporary = TEMPORARY_NAMES.read_text(encoding="utf-8")
        for source in ("src/stdio/tmpnam.c", "src/stdio/tempnam.c", "src/temp/__randname.c"):
            self.assertIn(source, temporary)
        self.assertIn("inherently racy", temporary)

        owned_filesystem = OWNED_FILESYSTEM.read_text(encoding="utf-8")
        self.assertIn("src/stat/lchmod.c", owned_filesystem)
        self.assertIn("AT_SYMLINK_NOFOLLOW", owned_filesystem)

    def test_runner_requires_one_installed_object_and_every_entry_mode(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for required in (
            "crabc-cc-dynamic\" --dynamic-pie",
            '"$work/workload.o"',
            "static static-pie",
            "pie non-pie",
            "kernel direct",
            "assert_posix_filesystem_symbols",
            "audit_consumer",
            "--link-receipt",
            "name_to_handle_at",
            "open_by_handle_at",
            "PTHREAD_CANCELED",
            "handles unavailable",
        ):
            self.assertIn(required, source)
        self.assertEqual(source.count('if [ -z "$provided_dynamic" ]; then'), 1)
        self.assertIn('if [ -z "${1:-}" ]; then', source)

        probe = PROBE.read_text(encoding="utf-8")
        for required in (
            "extern int __xstat",
            "readdir_r",
            "scandir",
            "pthread_cancel",
            "pthread_testcancel",
            "mktemp",
            "tempnam",
            "name_to_handle_at",
            "open_by_handle_at",
        ):
            self.assertIn(required, probe)

    def test_dynamic_qualification_replays_the_composed_runner(self) -> None:
        source = QUALIFICATION.read_text(encoding="utf-8")
        self.assertIn(
            '"posix-filesystem": ("run_owned_posix_filesystem.sh", None)',
            source,
        )

    def test_supplied_product_escape_is_rejected_before_building(self) -> None:
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            result = subprocess.run(
                ["bash", str(RUNNER), str(ROOT)],
                env={**os.environ, "TMPDIR": temporary},
                text=True,
                capture_output=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "owned POSIX filesystem product must be a checkout .work directory",
            result.stderr,
        )
        self.assertNotIn("evidence:", result.stdout)


if __name__ == "__main__":
    unittest.main()
