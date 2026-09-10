#!/usr/bin/env python3
"""Observable contract tests for the finite native package corpus."""
from __future__ import annotations

import importlib.util
import os
import sys
import tarfile
import tempfile
import tomllib
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run_x86.py"
SPEC = importlib.util.spec_from_file_location("crabc_corpus_runner_x86", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class NativeManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = RUNNER.load_manifest()

    def test_native_manifest_seals_the_unchanged_34_case_workload(self) -> None:
        with self.manifest.source_manifest.open("rb") as stream:
            source = tomllib.load(stream)
        expected = [
            {"id": case["id"], "tier": case["tier"], "package": case["package"], "path": case["path"], "argv": case["argv"],
             "stdin": case.get("stdin", ""), "setup": case.get("setup", []), "cwd": case.get("cwd", "/tmp"),
             "stateful": case.get("stateful", False), "requires_dt_relr": case.get("requires_dt_relr", False)}
            for case in source["cases"]
        ]
        actual = [
            {"id": case.id, "tier": case.tier, "package": case.package, "path": case.path, "argv": list(case.argv),
             "stdin": case.stdin.decode("utf-8"), "setup": [{"path": item.path, "contents": item.contents.decode("utf-8")} for item in case.setup],
             "cwd": case.cwd, "stateful": case.stateful, "requires_dt_relr": case.requires_dt_relr}
            for case in self.manifest.cases
        ]
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 34)

    def test_native_archive_closure_and_version_deltas_are_finite(self) -> None:
        with self.manifest.source_manifest.open("rb") as stream:
            source_packages = tomllib.load(stream)["packages"]
        self.assertEqual(len(self.manifest.archive_roster), 59)
        self.assertEqual(self.manifest.excluded_archives, {"musl-1.2.6-r2.apk"})
        self.assertEqual(
            {name for name, version in self.manifest.direct_packages.items() if version != source_packages[list(self.manifest.direct_packages).index(name)]["version"]},
            {"gzip", "sqlite", "curl", "openssl", "openssh-client-default"},
        )


class PrivatePayloadTests(unittest.TestCase):
    def test_archive_members_reject_traversal_before_extraction(self) -> None:
        with self.assertRaises(RUNNER.CorpusError):
            RUNNER.safe_archive_members(["../outside"])
        with self.assertRaises(RUNNER.CorpusError):
            RUNNER.safe_archive_members(["/outside"])

    def test_archive_roster_rejects_missing_and_unpinned_payloads(self) -> None:
        with self.assertRaises(RUNNER.CorpusError):
            RUNNER.require_exact_archive_roster(["one.apk"], ["one.apk", "two.apk"])
        with self.assertRaises(RUNNER.CorpusError):
            RUNNER.require_exact_archive_roster(["one.apk", "extra.apk"], ["one.apk"])

    def test_hardlink_targets_are_archive_root_relative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            archive = Path(temporary) / "payload.tar"
            with tarfile.open(archive, "w") as stream:
                info = tarfile.TarInfo("bin/tool")
                data = b"payload"
                info.size = len(data)
                import io
                stream.addfile(info, io.BytesIO(data))
                link = tarfile.TarInfo("usr/bin/tool")
                link.type = tarfile.LNKTYPE
                link.linkname = "bin/tool"
                stream.addfile(link)
            RUNNER.extract_archive(archive, root)
            self.assertEqual((root / "usr/bin/tool").read_bytes(), b"payload")

    def test_apk_metadata_accepts_the_signed_alpine_spacing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "fixture-1.0-r0.apk"
            with tarfile.open(archive, "w:gz") as stream:
                metadata = b"pkgname = fixture\npkgver = 1.0-r0\narch = x86_64\n"
                info = tarfile.TarInfo(".PKGINFO")
                info.size = len(metadata)
                import io
                stream.addfile(info, io.BytesIO(metadata))
            self.assertEqual(RUNNER.apk_metadata(archive), {"pkgname": "fixture", "pkgver": "1.0-r0", "arch": "x86_64"})

    def test_apk_metadata_accepts_noarch_payloads_from_the_x86_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "fixture-1.0-r0.apk"
            with tarfile.open(archive, "w:gz") as stream:
                metadata = b"pkgname = fixture\npkgver = 1.0-r0\narch = noarch\n"
                info = tarfile.TarInfo(".PKGINFO")
                info.size = len(metadata)
                import io
                stream.addfile(info, io.BytesIO(metadata))
            self.assertEqual(RUNNER.apk_metadata(archive)["arch"], "noarch")

    def test_absolute_payload_symlink_resolves_inside_private_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            (root / "program").write_bytes(b"program")
            (root / "bin/start").symlink_to("/program")
            self.assertEqual(RUNNER.resolve_payload_path(root, "/bin/start"), root / "program")

    def test_foreign_libc_in_private_payload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "lib").mkdir()
            (root / "usr/lib").mkdir(parents=True)
            loader = root / "lib/ld-musl-x86_64.so.1"
            libc = root / "lib/libc.musl-x86_64.so.1"
            loader.write_bytes(b"loader")
            libc.write_bytes(b"libc")
            (root / "usr/lib/libc.so").write_bytes(b"foreign")
            runtime = {"loader": {"sha256": RUNNER.sha256_file(loader, "loader")}, "libc": {"sha256": RUNNER.sha256_file(libc, "libc")}}
            with self.assertRaises(RUNNER.CorpusError):
                RUNNER.assert_runtime_boundary(root, runtime)

    @unittest.skipUnless(os.geteuid() == 0, "private character devices require root")
    def test_private_base_records_a_real_sealed_null_device(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            record = RUNNER.stage_base_image_fixtures(RUNNER.load_manifest(), root)
            node = (root / "dev/null").lstat()
            self.assertTrue(__import__("stat").S_ISCHR(node.st_mode))
            self.assertEqual((node.st_mode & 0o777, os.major(node.st_rdev), os.minor(node.st_rdev)), (0o666, 1, 3))
            self.assertEqual(record["device"]["kind"], "character")
            self.assertEqual(len(RUNNER.tree_sha256(root, "private root")), 64)


class RawOutcomeTests(unittest.TestCase):
    def test_dynamic_tag_match_does_not_accept_a_longer_tag(self) -> None:
        self.assertTrue(RUNNER.has_dynamic_tag("0x24 (RELR) 0x100\n", "RELR"))
        self.assertFalse(RUNNER.has_dynamic_tag("0x24 (RELRSZ) 0x100\n", "RELR"))

    def test_identical_nonzero_outcomes_never_become_a_pass(self) -> None:
        result = RUNNER.compare_results(RUNNER.ProcessResult(1, b"", b"failure\n"), RUNNER.ProcessResult(1, b"", b"failure\n"))
        self.assertTrue(result["status_match"])
        self.assertFalse(result["passed"])

    def test_any_raw_status_difference_is_retained(self) -> None:
        result = RUNNER.compare_results(RUNNER.ProcessResult(0, b"ok\n", b""), RUNNER.ProcessResult(127, b"", b"mainelf\n"))
        self.assertFalse(result["status_match"])
        self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main()
