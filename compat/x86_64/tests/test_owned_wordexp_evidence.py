#!/usr/bin/env python3
"""Rejection boundaries for retained owned-wordexp product evidence."""

from __future__ import annotations

import importlib.util
import shutil
import stat
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat/x86_64/owned_wordexp_evidence.py"
TMP_ROOT = ROOT / ".work/x86_64/test-owned-wordexp-evidence"


def load_module():
    spec = importlib.util.spec_from_file_location("owned_wordexp_evidence", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OwnedWordexpExecutionRootTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.root = TMP_ROOT / self.id().replace(".", "-")
        shutil.rmtree(self.root, ignore_errors=True)
        (self.root / "bin").mkdir(parents=True)
        self._write("consumer-pie", b"owned consumer\n", 0o755)
        self._write("oracle", b"musl oracle\n", 0o755)
        self._write("bin/sh", b"sealed external shell\n", 0o755)
        self._write("lib/libfixture.so", b"sealed shell dependency\n", 0o644)
        self._write("dev/null", b"", 0o666)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _write(self, relative: str, data: bytes, mode: int) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)

    def _record(self):
        return self.module.record_execution_root(
            self.root,
            product_files={},
            product_aliases={},
            consumers={"consumer": "consumer-pie", "oracle": "oracle"},
            fixture_files={
                "shell": "bin/sh",
                "shell-dependency": "lib/libfixture.so",
                "null": "dev/null",
            },
        )

    def test_extra_execution_file_is_rejected(self) -> None:
        record = self._record()
        self._write("unexpected", b"not part of the sealed root", 0o644)
        with self.assertRaises(self.module.EvidenceError):
            self.module.validate_execution_root(self.root, record)

    def test_changed_shell_fixture_mode_or_bytes_is_rejected(self) -> None:
        record = self._record()
        shell = self.root / "bin/sh"
        shell.write_bytes(b"substituted shell\n")
        shell.chmod(0o644)
        with self.assertRaises(self.module.EvidenceError):
            self.module.validate_execution_root(self.root, record)

    def test_product_aliases_are_bound_and_extra_aliases_rejected(self) -> None:
        self._write("lib/libc.so.1", b"product payload\n", 0o755)
        (self.root / "lib/libc.so").symlink_to("libc.so.1")
        record = self.module.record_execution_root(
            self.root,
            product_files={"runtime": "lib/libc.so.1"},
            product_aliases={"libc": "lib/libc.so"},
            consumers={"consumer": "consumer-pie", "oracle": "oracle"},
            fixture_files={
                "shell": "bin/sh",
                "shell-dependency": "lib/libfixture.so",
                "null": "dev/null",
            },
        )
        (self.root / "lib/extra-alias").symlink_to("libc.so.1")
        with self.assertRaises(self.module.EvidenceError):
            self.module.validate_execution_root(self.root, record)


if __name__ == "__main__":
    unittest.main()
