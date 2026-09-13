#!/usr/bin/env python3
"""Replay the native x86 `tgkill` provider shape from retained readelf text.

Pinned musl deliberately has no public `tgkill` symbol.  Its side of the
runtime comparison is a separately linked syscall adapter, so these raw musl
library tables must prove absence while the candidate's archive, `.dynsym`,
and full shared `.symtab` each prove one strong default-visible definition.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Any


class NativeThreadSignalSymbolError(ValueError):
    """A retained `tgkill` ABI observation is incomplete or changed."""


_TABLE_HEADER = re.compile(r"^Symbol table '([^']+)' contains ([0-9]+) entries:$")
_SYMBOL = re.compile(
    r"^\s*([0-9]+):\s+([0-9a-fA-F]+)\s+([0-9]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*?))?\s*$"
)
_SCHEMA = "crabc.x86_64-native-thread-signal-abi/v1"
_FROZEN = {
    "commit": "3e100d45c5a0798c2d3862d5e2eef584c610ccf9",
    "source": "libc/src/c_abi.rs::tgkill",
    "signature": "int tgkill(int, int, int)",
}
_LINUX = {"syscall": "tgkill", "number": 234, "errno_boundary": "kernel errno through c_status"}
_MUSL = {
    "release": "1.2.6",
    "revision": "9fa28ece75d8a2191de7c5bb53bed224c5947417",
    "public_tgkill_export": False,
    "adapter": "compat/x86_64/native_thread_signal_oracle_adapter.c",
}
_CANDIDATE = {
    "name": "tgkill",
    "raw_name": "tgkill",
    "version": None,
    "version_default": False,
    "type": "FUNC",
    "binding": "GLOBAL",
    "visibility": "DEFAULT",
}
_HEADER_VISIBILITY = {
    "gnu_cpp17": {
        "source": "compat/x86_64/native_thread_signal_header_gnu.cc",
        "defines": ["_GNU_SOURCE"],
        "reference": "unmangled tgkill",
    },
    "strict_cpp17": {
        "source": "compat/x86_64/native_thread_signal_header_strict.cc",
        "undefines": ["_GNU_SOURCE", "_BSD_SOURCE", "_DEFAULT_SOURCE", "_ALL_SOURCE"],
        "required_diagnostic": "undeclared identifier 'tgkill'",
    },
}


def _fail(message: str) -> None:
    raise NativeThreadSignalSymbolError(message)


def _load_contract(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"cannot read native thread-signal contract {path}: {error}")
    expected = {
        "schema", "frozen_crabc", "linux_x86_64", "musl_oracle", "candidate_symbol",
        "header_visibility",
        "family_completion", "promotion_ready", "public_support",
    }
    if not isinstance(value, dict) or set(value) != expected:
        _fail("unexpected native thread-signal contract shape")
    if (value["schema"] != _SCHEMA or value["frozen_crabc"] != _FROZEN
            or value["linux_x86_64"] != _LINUX or value["musl_oracle"] != _MUSL
            or value["candidate_symbol"] != _CANDIDATE
            or value["header_visibility"] != _HEADER_VISIBILITY):
        _fail("native thread-signal contract provenance or ABI shape changed")
    if any(value[flag] is not False for flag in ("family_completion", "promotion_ready", "public_support")):
        _fail("native thread-signal contract must remain non-promoting booleans")
    return value


def _split_symbol_name(raw_name: str) -> tuple[str, str | None, bool]:
    """Keep readelf's spelling while separating the ELF version identity."""

    if not raw_name:
        return "", None, False
    spelling = raw_name.split(" ", 1)[0]
    suffix = raw_name[len(spelling):]
    if suffix and not re.fullmatch(r" \([1-9][0-9]*\)", suffix):
        _fail(f"invalid retained symbol name spelling: {raw_name}")
    if "@@" in spelling:
        name, version = spelling.split("@@", 1)
        if not name or not version or "@" in version:
            _fail(f"invalid default symbol version spelling: {raw_name}")
        return name, version, True
    if "@" in spelling:
        name, version = spelling.split("@", 1)
        if not name or not version or "@" in version:
            _fail(f"invalid symbol version spelling: {raw_name}")
        return name, version, False
    return spelling, None, False


def parse_symbols(path: Path, *, archive: bool, table: str) -> list[dict[str, object]]:
    """Parse complete selected `readelf -W` tables; never hide a truncated row."""

    if table not in {".dynsym", ".symtab"}:
        _fail(f"unsupported selected symbol table: {table}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        _fail(f"cannot read retained symbol text {path}: {error}")

    records: list[dict[str, object]] = []
    current_file = ""
    current_table: str | None = None
    expected_count: int | None = None
    indexes: set[int] = set()
    selected_tables = 0

    def finish_table() -> None:
        nonlocal current_table, expected_count, indexes, selected_tables
        if current_table != table:
            current_table = None
            expected_count = None
            indexes = set()
            return
        if expected_count is None or indexes != set(range(expected_count)):
            _fail(f"selected symbol table {table} in {path} is truncated or malformed")
        selected_tables += 1
        current_table = None
        expected_count = None
        indexes = set()

    for raw in lines:
        if archive and raw.startswith("File: "):
            finish_table()
            current_file = raw[6:].strip()
            if not current_file:
                _fail(f"archive symbol table in {path} has an empty File attribution")
            continue
        header = _TABLE_HEADER.match(raw)
        if header is not None:
            finish_table()
            current_table, count_text = header.groups()
            expected_count = int(count_text)
            indexes = set()
            continue
        if current_table != table:
            continue
        match = _SYMBOL.match(raw)
        if match is None:
            continue
        index_text, value, size, kind, binding, visibility, section, name = match.groups()
        index = int(index_text)
        if expected_count is None or index >= expected_count or index in indexes:
            _fail(f"selected symbol table {table} in {path} has an invalid row index {index}")
        if archive and not current_file:
            _fail(f"archive symbol row in {path} lacks a File attribution")
        indexes.add(index)
        raw_name = name or ""
        symbol_name, version, version_default = _split_symbol_name(raw_name)
        records.append({
            "file": current_file,
            "index": index_text,
            "value": value.lower(),
            "size": size,
            "type": kind,
            "binding": binding,
            "visibility": visibility,
            "section": section,
            "raw_name": raw_name,
            "name": symbol_name,
            "version": version,
            "version_default": version_default,
        })
    finish_table()
    if selected_tables == 0:
        _fail(f"retained readelf text {path} has no {table} table")
    return records


def _defined(records: list[dict[str, object]]) -> list[dict[str, object]]:
    return [record for record in records if record["name"] == "tgkill" and record["section"] != "UND"]


def _require_absent(records: list[dict[str, object]], role: str) -> dict[str, object]:
    definitions = _defined(records)
    if definitions:
        _fail(f"{role} must retain musl's absent public tgkill ABI, found {len(definitions)} definitions")
    return {"public_tgkill_export": False}


def _require_candidate(records: list[dict[str, object]], role: str) -> dict[str, object]:
    definitions = _defined(records)
    if len(definitions) != 1:
        _fail(f"{role} requires exactly one defined tgkill, found {len(definitions)}")
    row = definitions[0]
    metadata = (row["type"], row["binding"], row["visibility"])
    expected = (_CANDIDATE["type"], _CANDIDATE["binding"], _CANDIDATE["visibility"])
    if metadata != expected:
        _fail(f"{role} tgkill must be {' '.join(expected)}, got {' '.join(metadata)}")
    identity = (row["raw_name"], row["version"], row["version_default"])
    expected_identity = (
        _CANDIDATE["raw_name"],
        _CANDIDATE["version"],
        _CANDIDATE["version_default"],
    )
    if identity != expected_identity:
        _fail(
            f"{role} tgkill must retain unversioned raw spelling "
            f"{_CANDIDATE['raw_name']!r} with null version and false defaultness, got {identity!r}"
        )
    return row


def validate(
    contract_path: Path,
    oracle_static_path: Path,
    oracle_dynamic_path: Path,
    oracle_shared_path: Path,
    candidate_static_path: Path,
    candidate_dynamic_path: Path,
    candidate_shared_path: Path,
) -> dict[str, object]:
    """Replay library symbol observations without tools or ambient inputs."""

    contract = _load_contract(contract_path)
    oracle_static = parse_symbols(oracle_static_path, archive=True, table=".symtab")
    oracle_dynamic = parse_symbols(oracle_dynamic_path, archive=False, table=".dynsym")
    oracle_shared = parse_symbols(oracle_shared_path, archive=False, table=".symtab")
    candidate_static = parse_symbols(candidate_static_path, archive=True, table=".symtab")
    candidate_dynamic = parse_symbols(candidate_dynamic_path, archive=False, table=".dynsym")
    candidate_shared = parse_symbols(candidate_shared_path, archive=False, table=".symtab")
    return {
        "schema": _SCHEMA,
        "contract": contract,
        "oracle": {
            "static": _require_absent(oracle_static, "oracle static archive"),
            "dynamic": _require_absent(oracle_dynamic, "oracle dynamic table"),
            "shared_symtab": _require_absent(oracle_shared, "oracle shared symtab"),
        },
        "candidate": {
            "static": _require_candidate(candidate_static, "candidate static archive"),
            "dynamic": _require_candidate(candidate_dynamic, "candidate dynamic table"),
            "shared_symtab": _require_candidate(candidate_shared, "candidate shared symtab"),
        },
    }


def main(argv: list[str]) -> int:
    if len(argv) != 9:
        raise SystemExit(
            "usage: native_thread_signal_abi_symbols.py CONTRACT ORACLE_STATIC ORACLE_DYNAMIC "
            "ORACLE_SHARED CANDIDATE_STATIC CANDIDATE_DYNAMIC CANDIDATE_SHARED OUTPUT"
        )
    result = validate(*(Path(argument) for argument in argv[1:8]))
    Path(argv[8]).write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except NativeThreadSignalSymbolError as error:
        raise SystemExit(f"native thread-signal ABI symbols: {error}")
