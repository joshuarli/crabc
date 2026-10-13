#!/usr/bin/env python3
"""Replay packed-relocation (RELR) text against the ELF it describes.

The fixture is a shared object linked with packed relative relocations by the
host linker, so the stream under test is real ``readelf`` output.
"""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


SOURCE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_DIR))

from owned_syscall_alias_authority import AuthorityError, require_relocation_stream

# Enough aligned pointer-sized data to need several RELR entries and at least
# one bitmap word with continuation rows.
FIXTURE_SOURCE = """
extern int a, b;
int a, b;
int *table[64] = { &a, &b, &a, &b, &a, &b, &a, &b, &a, &b };
const char *names[] = { "x", "y", "z" };
"""


class OwnedSyscallAliasRelrAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("clang")
        if compiler is None or shutil.which("ld.lld") is None or shutil.which("readelf") is None:
            raise unittest.SkipTest("requires clang, ld.lld, and readelf for a packed-relocation fixture")
        cls.scratch = SOURCE_DIR.parents[1] / ".work/x86_64/syscall-alias-relr-tests"
        cls.scratch.mkdir(parents=True, exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(dir=cls.scratch)
        cls.addClassCleanup(cls.temporary.cleanup)
        work = Path(cls.temporary.name)
        source = work / "fixture.c"
        source.write_text(FIXTURE_SOURCE)
        cls.elf = work / "libfixture.so"
        subprocess.run([compiler, "-shared", "-fPIC", "-fuse-ld=lld", "-Wl,-z,pack-relative-relocs",
                        str(source), "-o", str(cls.elf)], check=True, capture_output=True)
        cls.stream = work / "relocations.txt"
        cls.stream.write_bytes(subprocess.run(["readelf", "--relocs", "--wide", str(cls.elf)],
                                              check=True, capture_output=True).stdout)

    def replay_changed(self, changed: str) -> None:
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            path = Path(directory) / "relocations.txt"
            path.write_text(changed)
            require_relocation_stream(path, self.elf)

    def source(self) -> str:
        text = self.stream.read_text()
        self.assertIn(".relr.dyn", text)
        return text

    def test_selected_packed_relr_stream_matches_the_elf(self) -> None:
        require_relocation_stream(self.stream, self.elf)

    def test_truncated_packed_targets_reject(self) -> None:
        source = self.source()
        row = re.search(r"^ {24}[0-9a-f]{16}  .*\n", source, re.M)
        self.assertIsNotNone(row, "fixture has no packed continuation row")
        with self.assertRaises(AuthorityError):
            self.replay_changed(source.replace(row.group(), "", 1))

    def test_changed_packed_word_and_target_reject(self) -> None:
        source = self.source()
        bitmap = re.search(r"^[0-9]{4}:  ([0-9a-f]{15})([13579bdf])", source, re.M)
        self.assertIsNotNone(bitmap, "fixture has no bitmap entry")
        address = re.search(r"^ {24}([0-9a-f]{16})  ", source, re.M)
        self.assertIsNotNone(address)
        moved = "%016x" % (int(address.group(1), 16) + 8)
        for before, after in (
            (bitmap.group(0), bitmap.group(1) + "%x" % (int(bitmap.group(2), 16) ^ 2)),
            (address.group(0), "                        " + moved + "  "),
        ):
            with self.subTest(before=before):
                with self.assertRaises(AuthorityError):
                    self.replay_changed(source.replace(before, after, 1))

    def test_packed_count_and_entry_index_reject_when_changed(self) -> None:
        source = self.source()
        header = re.search(r"contains (\d+) entries which relocate (\d+) locations:", source)
        self.assertIsNotNone(header)
        index = re.search(r"^0001:", source, re.M)
        self.assertIsNotNone(index)
        for before, after in (
            (header.group(0), "contains %s entries which relocate %d locations:" % (
                header.group(1), int(header.group(2)) - 1)),
            (index.group(0), "0002:"),
        ):
            with self.subTest(before=before):
                with self.assertRaises(AuthorityError):
                    self.replay_changed(source.replace(before, after, 1))

    def test_malformed_packed_row_and_unproven_symbolic_target_reject(self) -> None:
        source = self.source()
        symbolic = re.search(r"^(\d{4}:  [0-9a-f]{16} [0-9a-f]{16}  )(\S+)", source, re.M)
        self.assertIsNotNone(symbolic)
        first = re.search(r"^0000:  ([0-9a-f]{15})[0-9a-f]", source, re.M)
        for before, after in (
            (first.group(0), "0000:  " + first.group(1) + "z"),
            (symbolic.group(0), symbolic.group(1) + "unproven_symbol"),
        ):
            with self.subTest(before=before):
                with self.assertRaises(AuthorityError):
                    self.replay_changed(source.replace(before, after, 1))


if __name__ == "__main__":
    unittest.main()
