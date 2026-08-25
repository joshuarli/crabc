"""Focused host-side tests for the sysroot distribution file boundary."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import platform
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("crabc_sysroot_dist_test", ROOT / "scripts/sysroot_dist.py")
assert SPEC is not None and SPEC.loader is not None
DIST = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DIST
SPEC.loader.exec_module(DIST)


def make_sysroot(root: Path) -> Path:
    sysroot = root / "sysroot"
    for relative in ("bin", "lib", "usr/include", "usr/lib", "share/crabc"):
        (sysroot / relative).mkdir(parents=True, exist_ok=True)
    (sysroot / "bin/crabc-cc").write_bytes(b"#!/bin/sh\n")
    (sysroot / "bin/crabc-cc").chmod(0o755)
    (sysroot / "share/crabc/crabc_sysroot.py").write_text("# driver\n", encoding="utf-8")
    (sysroot / "share/crabc/purity.json").write_text("{}\n", encoding="utf-8")
    runtime = {
        "libc.so": b"libc shared",
        "libc.a": b"libc static",
        "libcrabc-builtins.a": b"builtins",
        "crt1.o": b"crt1",
        "Scrt1.o": b"Scrt1",
        "rcrt1.o": b"rcrt1",
        "crti.o": b"crti",
        "crtn.o": b"crtn",
    }
    for name, contents in runtime.items():
        (sysroot / "usr/lib" / name).write_bytes(contents)
    (sysroot / "lib/ld-crabc-aarch64.so.1").write_bytes(b"loader")
    (sysroot / "lib/ld-musl-aarch64.so.1").symlink_to("ld-crabc-aarch64.so.1")
    for name in ("libm.so", "libdl.so", "libpthread.so", "librt.so", "libutil.so"):
        (sysroot / "usr/lib" / name).symlink_to("libc.so")
    artifacts = {
        name: {
            "path": f"usr/lib/{name}",
            "sha256": DIST.sha256_file(sysroot / "usr/lib" / name),
        }
        for name in runtime
    }
    artifacts["loader"] = {
        "path": "lib/ld-crabc-aarch64.so.1",
        "sha256": DIST.sha256_file(sysroot / "lib/ld-crabc-aarch64.so.1"),
    }
    manifest = {
        "schema": 1,
        "target": DIST.TARGET_TRIPLE,
        "platform": {"os": "linux", "architecture": "aarch64", "endianness": "little", "kernel_minimum": "5.10"},
        "canonical_interpreter": DIST.CANONICAL_INTERPRETER,
        "artifacts": artifacts,
    }
    (sysroot / "share/crabc/manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return sysroot


class NativeBoundaryTests(unittest.TestCase):
    def test_requires_native_linux_aarch64(self) -> None:
        with mock.patch.object(platform, "system", return_value="Darwin"):
            with self.assertRaises(DIST.DistError):
                DIST.require_native_aarch64()


class ValidationTests(unittest.TestCase):
    SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567"

    def test_validates_manifest_layout_and_relative_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inventory = DIST.validate_sysroot(make_sysroot(Path(temporary)))
        self.assertEqual(inventory.manifest["schema"], 1)
        self.assertTrue(inventory.symlinks)

    def test_rejects_absolute_or_escaping_sysroot_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = make_sysroot(Path(temporary))
            (sysroot / "usr/include/escape").symlink_to("../../../outside")
            with self.assertRaises(DIST.DistError):
                DIST.validate_sysroot(sysroot)

    def test_rejects_wrong_manifest_identity_and_missing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = make_sysroot(Path(temporary))
            manifest_path = sysroot / "share/crabc/manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["target"] = "wrong-target"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(DIST.DistError):
                DIST.validate_sysroot(sysroot)
            manifest["target"] = DIST.TARGET_TRIPLE
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (sysroot / "usr/lib/libc.a").unlink()
            with self.assertRaises(DIST.DistError):
                DIST.validate_sysroot(sysroot)

    def test_stage_injects_source_commit_without_mutating_source_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = make_sysroot(root)
            original = json.loads((source / "share/crabc/manifest.json").read_text(encoding="utf-8"))
            staged = DIST.stage_sysroot(source, root / "staged", source_commit=self.SOURCE_COMMIT, epoch=17)
            package = json.loads((staged / "share/crabc/manifest.json").read_text(encoding="utf-8"))
            self.assertNotIn("source_commit", original)
            self.assertEqual(package["source_commit"], self.SOURCE_COMMIT)
            self.assertEqual(json.loads((source / "share/crabc/manifest.json").read_text()), original)
            self.assertEqual(staged.stat().st_mtime_ns // 1_000_000_000, 17)
            DIST.validate_packaged_tree(staged, expected_source_commit=self.SOURCE_COMMIT)
            with self.assertRaises(DIST.DistError):
                DIST.validate_packaged_tree(staged, expected_source_commit="f" * 40)

    def test_rejects_manifest_artifact_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = make_sysroot(Path(temporary))
            manifest_path = sysroot / "share/crabc/manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["artifacts"]["libc.so"]["sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(DIST.DistError):
                DIST.validate_sysroot(sysroot)

    def test_rejects_embedded_build_path_in_runtime_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = make_sysroot(Path(temporary))
            artifact = sysroot / "usr/lib/libc.so"
            artifact.write_bytes(b"/workspace/target/crabc-sysroot")
            manifest_path = sysroot / "share/crabc/manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["artifacts"]["libc.so"]["sha256"] = DIST.sha256_file(artifact)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(DIST.DistError):
                DIST.validate_sysroot(sysroot)


class ArchiveTests(unittest.TestCase):
    def test_deterministic_tar_xz_and_safe_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = make_sysroot(root)
            (source / "usr/include/header.h").write_text("#define X 1\n", encoding="utf-8")
            first = DIST.create_deterministic_archive(source, root / "one.tar.xz", epoch=123)
            os.utime(source / "usr/include/header.h", (9999, 9999))
            second = DIST.create_deterministic_archive(source, root / "two.tar.xz", epoch=123)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first, "r:xz") as stream:
                for member in stream.getmembers():
                    self.assertEqual(member.mtime, 123)
                    self.assertEqual((member.uid, member.gid, member.uname, member.gname), (0, 0, "", ""))
                modes = {member.name: member.mode for member in stream.getmembers()}
            self.assertEqual(modes["crabc-sysroot"], 0o755)
            self.assertEqual(modes["crabc-sysroot/usr/include/header.h"], 0o644)
            self.assertEqual(modes["crabc-sysroot/bin/crabc-cc"], 0o755)
            self.assertTrue(DIST.validate_archive(first))
            extracted = DIST.safe_extract_archive(first, root / "extract")
            self.assertEqual((extracted / "usr/include/header.h").read_text(), "#define X 1\n")
            self.assertEqual(os.readlink(extracted / "lib/ld-musl-aarch64.so.1"), "ld-crabc-aarch64.so.1")

    def test_rejects_traversal_absolute_symlink_hardlink_and_special_members(self) -> None:
        cases = ("../escape", "/absolute", "crabc-sysroot/../escape")
        for member_name in cases:
            with self.subTest(member_name=member_name), tempfile.TemporaryDirectory() as temporary:
                archive = Path(temporary) / "bad.tar.xz"
                with tarfile.open(archive, "w:xz") as stream:
                    root_member = tarfile.TarInfo("crabc-sysroot")
                    root_member.type = tarfile.DIRTYPE
                    stream.addfile(root_member)
                    bad = tarfile.TarInfo(member_name)
                    bad.size = 1
                    stream.addfile(bad, io.BytesIO(b"x"))
                with self.assertRaises(DIST.DistError):
                    DIST.validate_archive(archive)

        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                archive = Path(temporary) / "bad.tar.xz"
                with tarfile.open(archive, "w:xz") as stream:
                    root_member = tarfile.TarInfo("crabc-sysroot")
                    root_member.type = tarfile.DIRTYPE
                    stream.addfile(root_member)
                    bad = tarfile.TarInfo("crabc-sysroot/bad")
                    if kind == "symlink":
                        bad.type = tarfile.SYMTYPE
                        bad.linkname = "../../outside"
                    elif kind == "hardlink":
                        bad.type = tarfile.LNKTYPE
                        bad.linkname = "crabc-sysroot/target"
                    else:
                        bad.type = tarfile.FIFOTYPE
                    stream.addfile(bad)
                with self.assertRaises(DIST.DistError):
                    DIST.validate_archive(archive)

        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "absolute-link.tar.xz"
            with tarfile.open(archive, "w:xz") as stream:
                root_member = tarfile.TarInfo("crabc-sysroot")
                root_member.type = tarfile.DIRTYPE
                stream.addfile(root_member)
                link = tarfile.TarInfo("crabc-sysroot/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "/outside"
                stream.addfile(link)
            with self.assertRaises(DIST.DistError):
                DIST.validate_archive(archive)

        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "root-escape-link.tar.xz"
            with tarfile.open(archive, "w:xz") as stream:
                root_member = tarfile.TarInfo("crabc-sysroot")
                root_member.type = tarfile.DIRTYPE
                stream.addfile(root_member)
                link = tarfile.TarInfo("crabc-sysroot/escape")
                link.type = tarfile.SYMTYPE
                link.linkname = ".."
                stream.addfile(link)
            with self.assertRaises(DIST.DistError):
                DIST.validate_archive(archive)


if __name__ == "__main__":
    unittest.main()
