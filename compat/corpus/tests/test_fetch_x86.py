#!/usr/bin/env python3
"""Input placement for the native package corpus (`fetch_x86.py`)."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

FETCH_PATH = Path(__file__).resolve().parents[1] / "fetch_x86.py"
SPEC = importlib.util.spec_from_file_location("crabc_corpus_fetch_x86", FETCH_PATH)
assert SPEC is not None and SPEC.loader is not None
FETCH = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FETCH
SPEC.loader.exec_module(FETCH)


class InstallTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
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

    def test_unpinned_index_snapshot_is_kept_until_refreshed(self) -> None:
        index = self.root / FETCH.INPUT / FETCH.INDEX_NAME
        with mock.patch.object(FETCH.urllib.request, "urlopen", return_value=io.BytesIO(b"first snapshot")):
            self.assertEqual(FETCH.install(FETCH.INDEX_NAME, None, "https://invalid/i", None), "download")
        with mock.patch.object(FETCH.urllib.request, "urlopen", side_effect=AssertionError("network used")):
            self.assertEqual(FETCH.install(FETCH.INDEX_NAME, None, "https://invalid/i", None), "present")
        with mock.patch.object(FETCH.urllib.request, "urlopen", return_value=io.BytesIO(b"regenerated snapshot")):
            self.assertEqual(FETCH.install(FETCH.INDEX_NAME, None, "https://invalid/i", None, refresh=True), "download")
        self.assertEqual(index.read_bytes(), b"regenerated snapshot")


if __name__ == "__main__":
    unittest.main()
