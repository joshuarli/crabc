#!/usr/bin/env python3
"""Input placement for the native package corpus (`fetch_x86.py`)."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

FETCH_PATH = Path(__file__).resolve().parents[1] / "fetch_x86.py"
SPEC = importlib.util.spec_from_file_location("crabc_corpus_fetch_x86", FETCH_PATH)
assert SPEC is not None and SPEC.loader is not None
FETCH = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FETCH
SPEC.loader.exec_module(FETCH)


def setUpModule() -> None:
    (FETCH_PATH.parents[2] / ".work").mkdir(exist_ok=True)


class InstallTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(dir=FETCH_PATH.parents[2] / ".work")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "checkout"
        self.seed = Path(temporary.name) / "primary-input"
        patcher = mock.patch.object(FETCH, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.pinned = b"pinned bytes"
        self.digest = hashlib.sha256(self.pinned).hexdigest()
        self.destination = self.root / FETCH.INPUT / "apks/fixture-1.apk"
        (self.seed / "apks").mkdir(parents=True)

    def test_matching_primary_copy_is_used_without_network(self) -> None:
        (self.seed / "apks/fixture-1.apk").write_bytes(self.pinned)
        with mock.patch.object(FETCH.urllib.request, "urlopen", side_effect=AssertionError("network used")):
            self.assertEqual(FETCH.install("apks/fixture-1.apk", self.digest, "https://invalid/x", self.seed), "primary checkout")
            self.assertEqual(FETCH.install("apks/fixture-1.apk", self.digest, "https://invalid/x", self.seed), "present")
        self.assertEqual(self.destination.read_bytes(), self.pinned)

    def test_mismatching_archive_bytes_are_never_installed_under_the_pin(self) -> None:
        (self.seed / "apks/fixture-1.apk").write_bytes(b"stale primary copy")
        with mock.patch.object(FETCH.urllib.request, "urlopen", return_value=io.BytesIO(b"substituted upstream")):
            with self.assertRaisesRegex(FETCH.FetchError, "differs from pinned"):
                FETCH.install("apks/fixture-1.apk", self.digest, "https://invalid/x", self.seed)
        self.assertEqual(list(self.destination.parent.iterdir()), [])

    def test_missing_canonical_archive_can_use_exact_pinned_mirror_bytes(self) -> None:
        canonical = "https://invalid/repo/fixture-1.apk"
        mirror = "https://mirror.invalid/repo/fixture-1.apk"
        missing = urllib.error.HTTPError(canonical, 404, "Not Found", {}, None)
        with mock.patch.object(FETCH.urllib.request, "urlopen", side_effect=[missing, io.BytesIO(self.pinned)]) as request:
            self.assertEqual(FETCH.install("apks/fixture-1.apk", self.digest, canonical, None,
                                           mirrors=(mirror,)), f"mirror {mirror}")
        self.assertEqual([call.args[0] for call in request.call_args_list], [canonical, mirror])
        self.assertEqual(self.destination.read_bytes(), self.pinned)

    def test_mirror_cannot_replace_an_unavailable_pin_with_changed_bytes(self) -> None:
        canonical = "https://invalid/repo/fixture-1.apk"
        missing = urllib.error.HTTPError(canonical, 404, "Not Found", {}, None)
        with mock.patch.object(FETCH.urllib.request, "urlopen", side_effect=[missing, io.BytesIO(b"changed")]):
            with self.assertRaisesRegex(FETCH.FetchError, "differs from pinned"):
                FETCH.install("apks/fixture-1.apk", self.digest, canonical, None,
                              mirrors=("https://mirror.invalid/repo/fixture-1.apk",))
        self.assertEqual(list(self.destination.parent.iterdir()), [])

    def test_unpinned_index_snapshot_is_kept_until_refreshed(self) -> None:
        index = self.root / FETCH.INPUT / FETCH.INDEX_NAME
        with mock.patch.object(FETCH.urllib.request, "urlopen", return_value=io.BytesIO(b"first snapshot")):
            self.assertEqual(FETCH.install(FETCH.INDEX_NAME, None, "https://invalid/i", None), "download")
        with mock.patch.object(FETCH.urllib.request, "urlopen", side_effect=AssertionError("network used")):
            self.assertEqual(FETCH.install(FETCH.INDEX_NAME, None, "https://invalid/i", None), "present")
        with mock.patch.object(FETCH.urllib.request, "urlopen", return_value=io.BytesIO(b"regenerated snapshot")):
            self.assertEqual(FETCH.install(FETCH.INDEX_NAME, None, "https://invalid/i", None, refresh=True), "download")
        self.assertEqual(index.read_bytes(), b"regenerated snapshot")


class MaterializeTests(unittest.TestCase):
    def test_unavailable_pin_does_not_hide_remaining_archives_or_index(self) -> None:
        with tempfile.TemporaryDirectory(dir=FETCH_PATH.parents[2] / ".work") as temporary:
            root = Path(temporary)
            manifest = root / "manifest.toml"
            manifest.write_text('[repository]\nbase_url = "https://invalid/repo"\n'
                                'index_filename = "APKINDEX.tar.gz"\n[archive_roster]\n'
                                '"absent.apk" = "' + "0" * 64 + '"\n'
                                '"available.apk" = "' + "1" * 64 + '"\n')
            calls = []
            def install(relative, *_args, **_kwargs):
                calls.append(relative)
                if relative == "apks/absent.apk":
                    raise urllib.error.HTTPError("https://invalid/repo/absent.apk", 404, "Not Found", {}, None)
                return "download"
            errors = io.StringIO()
            with mock.patch.object(FETCH, "ROOT", root), mock.patch.object(FETCH, "MANIFEST", manifest), \
                    mock.patch.object(FETCH, "primary_input", return_value=None), \
                    mock.patch.object(FETCH, "install", side_effect=install), contextlib.redirect_stderr(errors):
                self.assertEqual(FETCH.main([]), 1)
            self.assertEqual(calls, ["apks/absent.apk", "apks/available.apk", FETCH.INDEX_NAME])
            self.assertIn("absent.apk", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
