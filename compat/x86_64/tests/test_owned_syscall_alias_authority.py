#!/usr/bin/env python3
"""Replay pinned ELF relocation text against the selected shared image."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest


SOURCE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_DIR))

from owned_syscall_alias_authority import AuthorityError, require_relocation_stream


class OwnedSyscallAliasRelrAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        value = os.environ.get("CRABC_SYSCALL_ALIAS_RELR_FIXTURE")
        if not value:
            raise unittest.SkipTest("set CRABC_SYSCALL_ALIAS_RELR_FIXTURE to retained ELF and readelf text")
        cls.fixture = Path(value).resolve()
        cls.elf = cls.fixture / "libc.so"
        cls.stream = cls.fixture / "relocations.txt"
        for path in (cls.elf, cls.stream):
            if not path.is_file() or path.is_symlink():
                raise AssertionError(f"missing physical RELR fixture: {path}")
        cls.scratch = SOURCE_DIR.parents[1] / ".work/x86_64/syscall-alias-relr-tests"
        cls.scratch.mkdir(parents=True, exist_ok=True)

    def replay_changed(self, changed: str) -> None:
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            path = Path(directory) / "relocations.txt"
            path.write_text(changed)
            require_relocation_stream(path, self.elf)

    def test_selected_packed_relr_stream_matches_the_elf(self) -> None:
        require_relocation_stream(self.stream, self.elf)

    def test_truncated_packed_targets_reject(self) -> None:
        source = self.stream.read_text()
        row = "                        0000000000126830  subprocs\n"
        self.assertIn(row, source)
        with self.assertRaises(AuthorityError):
            self.replay_changed(source.replace(row, "", 1))

    def test_changed_packed_word_and_target_reject(self) -> None:
        source = self.stream.read_text()
        for before, after in (
            ("0001:  aaaaaaaaaaaacfe7", "0001:  aaaaaaaaaaaacfe5"),
            ("000000000011ba68  .tdata + 0x248", "000000000011ba70  .tdata + 0x250"),
        ):
            with self.subTest(before=before):
                self.assertIn(before, source)
                with self.assertRaises(AuthorityError):
                    self.replay_changed(source.replace(before, after, 1))

    def test_packed_count_and_entry_index_reject_when_changed(self) -> None:
        source = self.stream.read_text()
        for before, after in (
            ("contains 33 entries which relocate 860 locations:",
             "contains 33 entries which relocate 859 locations:"),
            ("0001:  aaaaaaaaaaaacfe7", "0002:  aaaaaaaaaaaacfe7"),
        ):
            with self.subTest(before=before):
                self.assertIn(before, source)
                with self.assertRaises(AuthorityError):
                    self.replay_changed(source.replace(before, after, 1))

    def test_malformed_packed_row_and_unproven_symbolic_target_reject(self) -> None:
        source = self.stream.read_text()
        for before, after in (
            ("0000:  000000000011ba58", "0000:  000000000011ba5z"),
            ("000000000011ba58  .tdata + 0x238", "000000000011ba58  .data + 0x238"),
        ):
            with self.subTest(before=before):
                self.assertIn(before, source)
                with self.assertRaises(AuthorityError):
                    self.replay_changed(source.replace(before, after, 1))
