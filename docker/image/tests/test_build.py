#!/usr/bin/env python3
"""Behavioral tests for the reproducible image builder's pure functions.

These run on the host without Docker. They cover rootfs normalization
(ordering, fixed mtime, numeric owners, hardlinks), config/manifest digest
derivation, mirror expansion, and lock parsing.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "build.py"
SPEC = importlib.util.spec_from_file_location("crabc_image_build", MODULE_PATH)
assert SPEC and SPEC.loader
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


def make_tree(root: Path) -> None:
    (root / "etc").mkdir(parents=True)
    (root / "etc/passwd").write_text("root:x:0:0::/:\n", encoding="utf-8")
    (root / "bin").mkdir()
    (root / "bin/tool").write_bytes(b"\x7fELFpayload")
    (root / "bin/tool").chmod(0o755)
    (root / "link").symlink_to("bin/tool")
    os.link(root / "bin/tool", root / "bin/tool-hardlink")
    os.utime(root / "etc/passwd", (1, 1))


def members(data: bytes) -> list[tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        return archive.getmembers()


class RootfsNormalizationTests(unittest.TestCase):
    def test_mtime_is_fixed_and_order_is_byte_sorted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_tree(root)
            first = build.normalize_rootfs(root, build.SOURCE_DATE_EPOCH)
            second = build.normalize_rootfs(root, build.SOURCE_DATE_EPOCH)
        self.assertEqual(first, second)
        infos = members(first)
        names = [info.name for info in infos]
        self.assertEqual(names, sorted(names, key=lambda name: name.encode()))
        self.assertTrue(all(info.mtime == build.SOURCE_DATE_EPOCH for info in infos))

    @unittest.skipUnless(os.geteuid() == 0, "numeric ownership needs root to set up")
    def test_owners_are_preserved_numerically_without_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_tree(root)
            os.chown(root / "etc", 4242, 4343)
            data = build.normalize_rootfs(root, build.SOURCE_DATE_EPOCH)
        entry = next(info for info in members(data) if info.name == "etc")
        self.assertEqual((entry.uid, entry.gid), (4242, 4343))
        self.assertEqual((entry.uname, entry.gname), ("", ""))

    def test_symlink_and_hardlink_are_represented(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_tree(root)
            data = build.normalize_rootfs(root, build.SOURCE_DATE_EPOCH)
        infos = {info.name: info for info in members(data)}
        self.assertTrue(infos["link"].issym())
        self.assertEqual(infos["link"].linkname, "bin/tool")
        self.assertTrue(infos["bin/tool-hardlink"].islnk())
        self.assertEqual(infos["bin/tool-hardlink"].linkname, "bin/tool")

    def test_no_xattrs_or_pax_extension_headers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_tree(root)
            data = build.normalize_rootfs(root, build.SOURCE_DATE_EPOCH)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for info in archive.getmembers():
                self.assertEqual(info.pax_headers, {})


class ImageIdentityTests(unittest.TestCase):
    def test_config_digest_is_stable_and_input_sensitive(self) -> None:
        first = build.image_config(build.SOURCE_DATE_EPOCH, "sha256:" + "0" * 64)
        second = build.image_config(build.SOURCE_DATE_EPOCH, "sha256:" + "0" * 64)
        other = build.image_config(build.SOURCE_DATE_EPOCH, "sha256:" + "1" * 64)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        document = json.loads(first)
        self.assertEqual(document["config"]["WorkingDir"], "/workspace")
        self.assertEqual(document["config"]["Cmd"], ["bash"])
        self.assertEqual(document["rootfs"]["diff_ids"], ["sha256:" + "0" * 64])

    def test_manifest_digest_depends_on_layer_and_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            layer = b"layer-bytes"
            first_id, _ = build.write_oci(out, layer, build.SOURCE_DATE_EPOCH)
            first_index = (out / "oci/index.json").read_bytes()
            second_id, _ = build.write_oci(out, layer, build.SOURCE_DATE_EPOCH)
            second_index = (out / "oci/index.json").read_bytes()
            other_id, _ = build.write_oci(out, b"other-layer", build.SOURCE_DATE_EPOCH)
        self.assertEqual(first_id, second_id)
        self.assertEqual(first_index, second_index)
        self.assertNotEqual(first_id, other_id)
        self.assertTrue(first_id.startswith("sha256:"))

    def test_written_layout_references_only_written_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            image_id, _ = build.write_oci(out, b"layer-bytes", build.SOURCE_DATE_EPOCH)
            blobs = {path.name for path in (out / "oci/blobs/sha256").iterdir()}
            index = json.loads((out / "oci/index.json").read_bytes())
            manifest_digest = index["manifests"][0]["digest"].split(":", 1)[1]
            self.assertEqual(index["manifests"][0]["digest"], image_id)
            self.assertIn(manifest_digest, blobs)
            manifest = json.loads((out / "oci/blobs/sha256" / manifest_digest).read_bytes())
            self.assertIn(manifest["config"]["digest"].split(":", 1)[1], blobs)
            self.assertIn(manifest["layers"][0]["digest"].split(":", 1)[1], blobs)

    def test_archive_tar_entries_are_sorted_with_fixed_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            build.write_oci(out, b"layer-bytes", build.SOURCE_DATE_EPOCH)
            with tarfile.open(out / "image.tar", mode="r:") as archive:
                infos = archive.getmembers()
        names = [info.name for info in infos]
        self.assertEqual(names, sorted(names))
        self.assertTrue(all(info.mtime == build.SOURCE_DATE_EPOCH for info in infos))
        self.assertIn("index.json", names)
        self.assertIn("oci-layout", names)


class LockParsingTests(unittest.TestCase):
    def test_entry_urls_rejects_non_https(self) -> None:
        with self.assertRaises(SystemExit):
            build.entry_urls({"name": "x", "urls": ["http://example.test/file"]})

    def test_entry_filename_falls_back_to_url_basename(self) -> None:
        item = {"name": "x", "urls": ["https://example.test/a/b/file.tgz"]}
        self.assertEqual(build.entry_filename(item), "file.tgz")

    def test_entry_filename_prefers_explicit_filename(self) -> None:
        item = {"name": "x", "filename": "pinned.tgz",
                "urls": ["https://example.test/a/b/other.tgz"]}
        self.assertEqual(build.entry_filename(item), "pinned.tgz")

    def test_read_lock_rejects_wrong_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text(json.dumps({"schema_version": 2, "inputs": []}), encoding="utf-8")
            with self.assertRaises(SystemExit):
                build.read_lock(path)

    def test_read_lock_requires_inputs_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
            with self.assertRaises(SystemExit):
                build.read_lock(path)

    def test_lock_entry_names_the_missing_input(self) -> None:
        with self.assertRaises(SystemExit):
            build.lock_entry([{"name": "present"}], "absent")


class FetchVerificationTests(unittest.TestCase):
    def test_pinned_bytes_are_reused_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b"locked-bytes"
            cached = root / "input" / "file.bin"
            cached.parent.mkdir(parents=True)
            cached.write_bytes(payload)
            import hashlib

            item = {"name": "input", "filename": "file.bin",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload), "urls": ["https://example.test/file.bin"]}
            self.assertEqual(build.fetch_verified(item, root), cached)

    def test_digest_mismatch_is_rejected_before_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cached = root / "input" / "file.bin"
            cached.parent.mkdir(parents=True)
            cached.write_bytes(b"tampered")
            item = {"name": "input", "filename": "file.bin", "sha256": "0" * 64,
                    "size": 8, "urls": ["https://example.test/file.bin"]}
            with self.assertRaises(SystemExit):
                build.fetch_verified(item, root)


if __name__ == "__main__":
    unittest.main()
