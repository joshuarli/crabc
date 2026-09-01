#!/usr/bin/env python3
"""Focused deterministic/safe package contracts for the owned static slice."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat" / "x86_64" / "owned_static_sysroot_package.py"
SPEC = importlib.util.spec_from_file_location("owned_static_sysroot_package", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
package = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = package
SPEC.loader.exec_module(package)


class OwnedStaticSysrootPackageTests(unittest.TestCase):
    def populate_tree(self, root: Path) -> None:
        (root / "bin").mkdir(parents=True)
        (root / "usr" / "include").mkdir(parents=True)
        (root / "usr" / "lib").mkdir(parents=True)
        (root / "bin" / "crabc-cc").write_text("#!/bin/sh\n", encoding="utf-8")
        (root / "bin" / "crabc-cc").chmod(0o755)
        (root / "usr" / "include" / "stdint.h").write_text("\n", encoding="utf-8")
        for name in ("crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o"):
            (root / "usr" / "lib" / name).write_bytes(f"{name}\n".encode("utf-8"))
        (root / "usr" / "lib" / "libc.a").write_bytes(b"owned static archive\n")
        (root / "usr" / "lib" / "libcrabc-builtins.a").write_bytes(
            b"owned compiler helpers\n"
        )
        payload = {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }
        manifest = {
            "format": "crabc-x86-64-owned-static-sysroot-v1",
            "target": "x86_64-unknown-linux-musl",
            "installed": {
                "headers": "usr/include",
                "crt_objects": [
                    "usr/lib/crt1.o",
                    "usr/lib/Scrt1.o",
                    "usr/lib/rcrt1.o",
                    "usr/lib/crti.o",
                    "usr/lib/crtn.o",
                ],
                "static_libc": "usr/lib/libc.a",
                "bounded_compiler_helpers": "usr/lib/libcrabc-builtins.a",
                "sealed_static_driver": "bin/crabc-cc",
                "files": payload,
            },
            "sealed_static_driver": {
                "format": "crabc-x86-64-sealed-static-driver-v1",
                "path": "bin/crabc-cc",
                "status": "planned-owned-static-product-seed-not-family-completion-not-public-support",
            },
            "package": {
                "format": package.PACKAGE_FORMAT,
                "archive_root": package.ARCHIVE_ROOT,
            },
        }
        manifest_path = root / "share" / "crabc" / "manifest.json"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
        )

    def test_archive_is_byte_reproducible_and_extraction_is_regular_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            self.populate_tree(source)
            first = workspace / "first.tar.xz"
            second = workspace / "second.tar.xz"
            package.create_archive(source, first)
            package.create_archive(source, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())

            destination = workspace / "extract"
            extracted = package.extract_archive(first, destination)
            self.assertEqual(
                (extracted / "usr" / "lib" / "libc.a").read_bytes(),
                b"owned static archive\n",
            )
            self.assertTrue((extracted / "bin" / "crabc-cc").stat().st_mode & 0o111)
            self.assertFalse(any(path.is_symlink() for path in extracted.rglob("*")))

    def test_packaging_refuses_a_symlinked_input_or_unsafe_member_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            self.populate_tree(source)
            (source / "usr" / "lib" / "alias.a").symlink_to("libc.a")
            with self.assertRaisesRegex(package.PackageError, "symlink"):
                package.create_archive(source, workspace / "unsafe.tar.xz")

    def test_packaging_rejects_an_unmanifested_or_tampered_source_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            unmanifested = workspace / "unmanifested"
            unmanifested.mkdir()
            with self.assertRaisesRegex(package.PackageError, "manifest"):
                package.create_archive(unmanifested, workspace / "unmanifested.tar.xz")

            for label, mutate, error in (
                (
                    "undeclared",
                    lambda root: (root / "usr" / "include" / "extra.h").write_text(
                        "#define EXTRA 1\n", encoding="utf-8"
                    ),
                    "undeclared installed regular file",
                ),
                (
                    "hash-mismatch",
                    lambda root: (root / "usr" / "lib" / "libc.a").write_bytes(
                        b"tampered archive\n"
                    ),
                    "payload hash mismatch",
                ),
            ):
                with self.subTest(label=label):
                    source = workspace / label
                    self.populate_tree(source)
                    mutate(source)
                    with self.assertRaisesRegex(package.PackageError, error):
                        package.create_archive(source, workspace / f"{label}.tar.xz")

    def test_packaging_rejects_archive_and_extraction_paths_through_ancestor_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            self.populate_tree(source)
            outside = workspace / "outside" / "nested"
            outside.mkdir(parents=True)
            redirected = workspace / "redirected"
            redirected.symlink_to(outside.parent, target_is_directory=True)
            with self.assertRaisesRegex(package.PackageError, "traverses an existing symlink"):
                package.create_archive(source, redirected / "nested" / "artifact.tar.xz")

            archive = workspace / "safe.tar.xz"
            package.create_archive(source, archive)
            with self.assertRaisesRegex(package.PackageError, "traverses an existing symlink"):
                package.extract_archive(archive, redirected / "nested" / "extract")

    def test_extraction_refuses_link_and_traversal_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            cases = (
                ("link", f"{package.ARCHIVE_ROOT}/alias", tarfile.SYMTYPE),
                ("traversal", f"{package.ARCHIVE_ROOT}/../escape", tarfile.REGTYPE),
            )
            for label, name, member_type in cases:
                with self.subTest(label=label):
                    archive = workspace / f"{label}.tar.xz"
                    with tarfile.open(archive, "w:xz") as output:
                        root = tarfile.TarInfo(package.ARCHIVE_ROOT)
                        root.type = tarfile.DIRTYPE
                        output.addfile(root)
                        member = tarfile.TarInfo(name)
                        member.type = member_type
                        if member_type == tarfile.SYMTYPE:
                            member.linkname = "target"
                        output.addfile(member)
                    with self.assertRaisesRegex(package.PackageError, "non-regular|unsafe"):
                        destination = workspace / f"{label}-extract"
                        package.extract_archive(archive, destination)
                    self.assertFalse(destination.exists())

    def test_extraction_rejects_an_unbound_archive_without_leaving_a_partial_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            archive = workspace / "unbound.tar.xz"
            with tarfile.open(archive, "w:xz") as output:
                root = tarfile.TarInfo(package.ARCHIVE_ROOT)
                root.type = tarfile.DIRTYPE
                output.addfile(root)
                content = b"unbound\n"
                member = tarfile.TarInfo(f"{package.ARCHIVE_ROOT}/usr/lib/libc.a")
                member.size = len(content)
                output.addfile(member, io.BytesIO(content))
            destination = workspace / "extract"
            with self.assertRaisesRegex(package.PackageError, "manifest"):
                package.extract_archive(archive, destination)
            self.assertFalse(destination.exists())

    def test_archive_member_limits_reject_untrusted_metadata_before_materialization(self) -> None:
        """Member count, individual size, and aggregate payload are bounded up front."""

        root = tarfile.TarInfo(package.ARCHIVE_ROOT)
        root.type = tarfile.DIRTYPE

        oversized = tarfile.TarInfo(f"{package.ARCHIVE_ROOT}/oversized")
        oversized.size = package.MAX_ARCHIVE_MEMBER_BYTES + 1
        with self.assertRaisesRegex(package.PackageError, "member exceeds"):
            package.checked_archive_members((root, oversized))

        aggregate = []
        for number in range(package.MAX_ARCHIVE_TOTAL_BYTES // package.MAX_ARCHIVE_MEMBER_BYTES + 1):
            member = tarfile.TarInfo(f"{package.ARCHIVE_ROOT}/aggregate-{number}")
            member.size = package.MAX_ARCHIVE_MEMBER_BYTES
            aggregate.append(member)
        with self.assertRaisesRegex(package.PackageError, "regular-payload"):
            package.checked_archive_members((root, *aggregate))

        count_limited = []
        for number in range(package.MAX_ARCHIVE_MEMBER_COUNT):
            count_limited.append(tarfile.TarInfo(f"{package.ARCHIVE_ROOT}/member-{number}"))
        with self.assertRaisesRegex(package.PackageError, "member safety limit"):
            package.checked_archive_members((root, *count_limited))

    def test_archive_publication_never_replaces_a_destination_created_at_publish(self) -> None:
        """A competitor's final pathname wins without receiving partial package bytes."""

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            self.populate_tree(source)
            archive = workspace / "artifact.tar.xz"
            original_validate = package.validate_installed_tree

            def validate_then_create_competing_archive(
                validated_source: Path, entries: list[tuple[Path, Path]]
            ) -> None:
                original_validate(validated_source, entries)
                self.assertEqual(validated_source, source)
                archive.write_bytes(b"competing artifact\n")

            with mock.patch.object(
                package,
                "validate_installed_tree",
                side_effect=validate_then_create_competing_archive,
            ):
                with self.assertRaisesRegex(package.PackageError, "already exists"):
                    package.create_archive(source, archive)
            self.assertEqual(archive.read_bytes(), b"competing artifact\n")

    def test_archive_path_inside_source_is_rejected_before_package_mutation(self) -> None:
        """The producer must not add its output to the manifest-bound source tree."""

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            self.populate_tree(source)
            archive = source / "artifact.tar.xz"
            with mock.patch.object(
                package.tarfile,
                "open",
                side_effect=AssertionError("archive writing must not begin"),
            ):
                with self.assertRaisesRegex(package.PackageError, "inside the source tree"):
                    package.create_archive(source, archive)
            self.assertFalse(archive.exists())

    def test_failed_archive_write_leaves_no_partial_requested_destination(self) -> None:
        """Only a fully written archive may become visible at the caller's pathname."""

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            self.populate_tree(source)
            archive = workspace / "artifact.tar.xz"
            original_addfile = package.tarfile.TarFile.addfile

            def fail_after_private_root(
                output: tarfile.TarFile, member: tarfile.TarInfo, fileobj: object = None
            ) -> None:
                if member.name != package.ARCHIVE_ROOT:
                    raise OSError("injected archive write failure")
                original_addfile(output, member, fileobj)

            with mock.patch.object(
                package.tarfile.TarFile, "addfile", new=fail_after_private_root
            ):
                with self.assertRaisesRegex(package.PackageError, "cannot create deterministic"):
                    package.create_archive(source, archive)
            self.assertFalse(archive.exists())

    def test_extraction_publication_never_replaces_a_destination_created_at_publish(self) -> None:
        """A competing empty directory wins over the staged extracted tree."""

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            self.populate_tree(source)
            archive = workspace / "artifact.tar.xz"
            package.create_archive(source, archive)
            destination = workspace / "extract"
            original_validate = package.validate_installed_tree

            def validate_then_create_competing_directory(
                validated_source: Path, entries: list[tuple[Path, Path]]
            ) -> None:
                original_validate(validated_source, entries)
                destination.mkdir()

            with mock.patch.object(
                package,
                "validate_installed_tree",
                side_effect=validate_then_create_competing_directory,
            ):
                with self.assertRaisesRegex(package.PackageError, "already exists"):
                    package.extract_archive(archive, destination)
            self.assertTrue(destination.is_dir())
            self.assertFalse((destination / package.ARCHIVE_ROOT).exists())


if __name__ == "__main__":
    unittest.main()
