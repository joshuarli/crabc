#!/usr/bin/env python3
"""Focused contract tests for native C compatibility-entry aliases."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "compat/x86_64/c_compatibility_entry_alias_symbols.py"
CONTRACT = ROOT / "compat/x86_64/c_compatibility_entry_aliases.json"

spec = importlib.util.spec_from_file_location("c_compatibility_entry_alias_symbols", MODULE_PATH)
assert spec and spec.loader
symbols = importlib.util.module_from_spec(spec)
spec.loader.exec_module(symbols)


class CompatibilityEntryAliasSymbolsTests(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def _row(index: int, value: int, size: int, kind: str, binding: str, visibility: str,
             section: str, name: str) -> str:
        return (
            f"{index:6}: {value:016x} {size:5} {kind:<7} {binding:<6} {visibility:<7} "
            f"{section:>5} {name}\n"
        )

    def _table(self, table: str, *, archive: bool = False, broken: str | None = None) -> str:
        entries: list[tuple[int, int, int, str, str, str, str, str]] = [
            (0, 0, 0, "NOTYPE", "LOCAL", "DEFAULT", "UND", ""),
        ]
        index = 1
        value = 0x1000
        for alias, target in symbols._WEAK_ALIASES.items():
            entries.append((index, value, 17, "FUNC", "WEAK", "DEFAULT", "10", alias))
            index += 1
            entries.append((index, value, 17, "FUNC", "GLOBAL", "DEFAULT", "10", target))
            index += 1
            value += 0x20
        for wrapper in symbols._STRONG_WRAPPERS:
            entries.append((index, value, 23, "FUNC", "GLOBAL", "DEFAULT", "10", wrapper))
            index += 1
            value += 0x20
        if broken == "mismatched-alias":
            alias, target = next(iter(symbols._WEAK_ALIASES.items()))
            entries = [
                (*entry[:1], entry[1] + 1 if entry[-1] == target else entry[1], *entry[2:])
                for entry in entries
            ]
        if broken == "weak-wrapper":
            wrapper = symbols._STRONG_WRAPPERS[0]
            entries = [
                (*entry[:4], "WEAK" if entry[-1] == wrapper else entry[4], *entry[5:])
                for entry in entries
            ]
        if broken == "truncated":
            entries.pop(3)
        prefix = "File: libc-entry.o\n" if archive else ""
        return prefix + f"Symbol table '{table}' contains {index} entries:\n" + "".join(
            self._row(*entry) for entry in entries
        )

    def _write_inputs(self, directory: Path, *, broken: str | None = None) -> list[Path]:
        paths: list[Path] = []
        for name, table, archive in (
            ("oracle-static", ".symtab", True),
            ("oracle-dynamic", ".dynsym", False),
            ("oracle-shared", ".symtab", False),
            ("candidate-static", ".symtab", True),
            ("candidate-dynamic", ".dynsym", False),
            ("candidate-shared", ".symtab", False),
        ):
            path = directory / name
            path.write_text(self._table(table, archive=archive, broken=broken if name.startswith("candidate") else None),
                            encoding="utf-8")
            paths.append(path)
        return paths

    def test_complete_archive_dynsym_and_shared_symtab_aliases_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_inputs(Path(temporary))
            result = symbols.validate(CONTRACT, *paths)
        self.assertEqual(result["schema"], "crabc.x86_64-c-compatibility-entry-aliases/v1")
        self.assertEqual(set(result["candidate"]["dynamic"]),
                         set(symbols._WEAK_ALIASES) | set(symbols._STRONG_WRAPPERS))
        pair = result["candidate"]["shared_symtab"]["__isoc99_sscanf"]
        self.assertEqual(pair["alias"]["value"], pair["target"]["value"])
        self.assertEqual(pair["alias"]["binding"], "WEAK")

    def test_alias_address_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_inputs(Path(temporary), broken="mismatched-alias")
            with self.assertRaisesRegex(symbols.CompatibilityEntryAliasError, "one definition"):
                symbols.validate(CONTRACT, *paths)

    def test_missing_declared_symbol_table_row_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_inputs(Path(temporary), broken="truncated")
            with self.assertRaisesRegex(symbols.CompatibilityEntryAliasError, "truncated or malformed"):
                symbols.validate(CONTRACT, *paths)

    def test_strong_xmknod_wrapper_cannot_be_weakened(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._write_inputs(Path(temporary), broken="weak-wrapper")
            with self.assertRaisesRegex(symbols.CompatibilityEntryAliasError, "wrapper metadata"):
                symbols.validate(CONTRACT, *paths)

    def test_numeric_non_promoting_flag_is_not_a_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
            contract["promotion_ready"] = 0
            path = Path(temporary) / "contract.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaisesRegex(symbols.CompatibilityEntryAliasError, "non-promoting"):
                symbols._load_contract(path)

    def test_runner_keeps_one_installed_object_and_all_required_execution_shapes(self) -> None:
        runner = (ROOT / "compat/x86_64/run_c_compatibility_entry_aliases.sh").read_text(encoding="utf-8")
        probe = (ROOT / "compat/x86_64/c_compatibility_entry_aliases_probe.c").read_text(encoding="utf-8")
        self.assertIn('"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie', runner)
        self.assertIn('candidate-static-pie-link', runner)
        self.assertIn('for mode in pie non-pie; do', runner)
        self.assertIn('for entry in kernel direct; do', runner)
        self.assertIn('readelf --dyn-syms -W "$dynamic_product/usr/lib/libc.so"', runner)
        self.assertIn('readelf -Ws "$dynamic_product/usr/lib/libc.so"', runner)
        self.assertIn('__isoc99_vfscanf', probe)
        self.assertIn('__strtoumax_internal', probe)
        self.assertIn('__xmknodat(11, -1', probe)


if __name__ == "__main__":
    unittest.main()
