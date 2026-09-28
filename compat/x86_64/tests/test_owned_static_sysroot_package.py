#!/usr/bin/env python3
"""Focused deterministic/safe package contracts for the owned static slice."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import lzma
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from compat.x86_64 import static_product_contract


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
            "source_sha256": static_product_contract.source_digest(),
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

    def test_rehashed_foreign_or_missing_source_seal_cannot_be_packaged_or_extracted(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            self.populate_tree(source)
            control = workspace / "control.tar.xz"
            package.create_archive(source, control)
            package.extract_archive(control, workspace / "control-extracted")
            with tarfile.open(control, "r:xz") as archive:
                members = [(copy.copy(member), archive.extractfile(member).read() if member.isfile() else None)
                           for member in archive.getmembers()]
            manifest_member = f"{package.ARCHIVE_ROOT}/share/crabc/manifest.json"
            for name in ("foreign", "stripped"):
                with self.subTest(name=name):
                    altered = workspace / name
                    package.extract_archive(control, altered)
                    manifest_path = altered / package.ARCHIVE_ROOT / "share/crabc/manifest.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    if name == "foreign":
                        manifest["source_sha256"] = "b" * 64
                    else:
                        del manifest["source_sha256"]
                    changed = (json.dumps(manifest, sort_keys=True) + "\n").encode()
                    manifest_path.write_bytes(changed)
                    with self.assertRaisesRegex(package.PackageError, "source seal"):
                        package.create_archive(altered / package.ARCHIVE_ROOT,
                                               workspace / f"{name}-repack.tar.xz")
                    forged = workspace / f"{name}.tar.xz"
                    with tarfile.open(forged, "w:xz") as archive:
                        for original, payload in members:
                            member = copy.copy(original)
                            if member.name == manifest_member:
                                payload = changed
                                member.size = len(changed)
                            archive.addfile(member, None if payload is None else io.BytesIO(payload))
                    destination = workspace / f"{name}-extracted"
                    with self.assertRaisesRegex(package.PackageError, "source seal"):
                        package.extract_archive(forged, destination)
                    self.assertFalse(destination.exists())

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

    def test_extraction_rejects_forged_member_modes(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            self.populate_tree(source)
            control = workspace / "control.tar.xz"
            package.create_archive(source, control)
            for relative, changed_mode in (("bin/crabc-cc", 0o644),
                                           ("usr/lib/libc.a", 0o777),
                                           ("", 0o700)):
                with self.subTest(relative=relative):
                    name = package.ARCHIVE_ROOT + ("/" + relative if relative else "")
                    label = relative.replace("/", "-") or "root"
                    forged = workspace / f"{label}.tar.xz"
                    with tarfile.open(control, "r:xz") as original, \
                         tarfile.open(forged, "w:xz") as rewritten:
                        for member in original.getmembers():
                            projected = copy.copy(member)
                            if projected.name == name:
                                projected.mode = changed_mode
                            payload = original.extractfile(member).read() if member.isfile() else None
                            rewritten.addfile(projected, None if payload is None else io.BytesIO(payload))
                    destination = workspace / f"rejected-{label}"
                    with self.assertRaisesRegex(package.PackageError, "mode"):
                        package.extract_archive(forged, destination)
                    self.assertFalse(destination.exists())
            (source / "bin/crabc-cc").chmod(0o644)
            with self.assertRaisesRegex(package.PackageError, "mode"):
                package.create_archive(source, workspace / "nonexecutable-driver.tar.xz")

    def test_extraction_rejects_noncanonical_tar_encoding(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            self.populate_tree(source)
            control = workspace / "control.tar.xz"
            package.create_archive(source, control)
            with tarfile.open(control, "r:xz") as opened:
                libc = opened.getmember(f"{package.ARCHIVE_ROOT}/usr/lib/libc.a")
                padding_offset = libc.offset_data + libc.size
            for variant in ("pax", "gnu", "reordered", "uid", "gid", "mtime", "padding"):
                with self.subTest(variant=variant):
                    forged = workspace / f"{variant}.tar.xz"
                    if variant == "padding":
                        raw = bytearray(lzma.decompress(control.read_bytes()))
                        self.assertEqual(raw[padding_offset], 0)
                        raw[padding_offset] = 1
                        forged.write_bytes(lzma.compress(raw))
                    else:
                        archive_format = tarfile.GNU_FORMAT if variant == "gnu" else tarfile.PAX_FORMAT
                        with tarfile.open(control, "r:xz") as original, \
                             tarfile.open(forged, "w:xz", format=archive_format) as rewritten:
                            members = original.getmembers()
                            if variant == "reordered":
                                members = [members[0], *reversed(members[1:])]
                            for member in members:
                                projected = copy.copy(member)
                                if variant == "pax" and member.name == package.ARCHIVE_ROOT:
                                    projected.pax_headers = {"comment": "forged"}
                                if variant in {"uid", "gid", "mtime"} and member.name.endswith("/usr/lib/libc.a"):
                                    setattr(projected, variant, 1)
                                payload = original.extractfile(member).read() if member.isfile() else None
                                rewritten.addfile(projected, None if payload is None else io.BytesIO(payload))
                    destination = workspace / f"rejected-{variant}"
                    with self.assertRaisesRegex(package.PackageError, "archive encoding"):
                        package.extract_archive(forged, destination)
                    self.assertFalse(destination.exists())

    def test_extraction_rejects_noncanonical_xz_wrapper(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            self.populate_tree(source)
            control = workspace / "control.tar.xz"
            package.create_archive(source, control)
            compressed = control.read_bytes()
            tar_bytes = lzma.decompress(compressed)
            for variant, encoded in (("trailing", compressed + b"trailing xz bytes"),
                                     ("preset9", lzma.compress(tar_bytes, format=lzma.FORMAT_XZ, preset=9))):
                with self.subTest(variant=variant):
                    self.assertNotEqual(encoded, compressed)
                    self.assertEqual(lzma.decompress(encoded), tar_bytes)
                    forged = workspace / f"{variant}.tar.xz"
                    forged.write_bytes(encoded)
                    destination = workspace / f"rejected-{variant}"
                    with self.assertRaisesRegex(package.PackageError, "xz encoding"):
                        package.extract_archive(forged, destination)
                    self.assertFalse(destination.exists())

    def test_writer_pax_long_path_remains_extractable(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            self.populate_tree(source)
            relative = Path("usr/include") / ("x" * 95 + ".h")
            payload = b"long installed header\n"
            (source / relative).write_bytes(payload)
            manifest_path = source / package.MANIFEST_RELATIVE_PATH
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["installed"]["files"][relative.as_posix()] = hashlib.sha256(payload).hexdigest()
            manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
            archive = workspace / "long-path.tar.xz"
            package.create_archive(source, archive)
            with tarfile.open(archive, "r:xz") as opened:
                member = opened.getmember(f"{package.ARCHIVE_ROOT}/{relative.as_posix()}")
                self.assertIn("path", member.pax_headers)
            extracted = package.extract_archive(archive, workspace / "extracted")
            self.assertEqual((extracted / relative).read_bytes(), payload)

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
                for name in (package.ARCHIVE_ROOT,
                             f"{package.ARCHIVE_ROOT}/usr",
                             f"{package.ARCHIVE_ROOT}/usr/lib"):
                    output.addfile(package.deterministic_info(name, directory=True, mode=0o755))
                content = b"unbound\n"
                member = tarfile.TarInfo(f"{package.ARCHIVE_ROOT}/usr/lib/libc.a")
                member.size = len(content)
                member.mode = 0o644
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
