#!/usr/bin/env python3
"""Replay the fixed musl compatibility-entry alias shape from readelf text.

The fourteen names are source-level ABI compatibility spellings, not a broad
stdio, integer, or filesystem API admission.  The twelve weak aliases must be
one definition with their ordinary selected target in every observed artifact;
``__xmknod`` and ``__xmknodat`` are separate strong musl wrappers.

Archive ``readelf -Ws`` data needs member attribution.  A shared ``-Ws`` dump
contains both ``.dynsym`` and ``.symtab``; callers choose one table so duplicate
rows from the two tables can never make an alias look ambiguous.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Any


class CompatibilityEntryAliasError(ValueError):
    """A retained symbol observation does not meet the fixed source contract."""


_TABLE_HEADER = re.compile(r"^Symbol table '([^']+)' contains ([0-9]+) entries:$")
_SYMBOL = re.compile(
    r"^\s*([0-9]+):\s+([0-9a-fA-F]+)\s+([0-9]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*?))?\s*$"
)
_SCHEMA = "crabc.x86_64-c-compatibility-entry-aliases/v1"
_ORACLE = {"release": "musl-1.2.6", "revision": "9fa28ece75d8a2191de7c5bb53bed224c5947417"}
_WEAK_ALIASES = {
    "__isoc99_fscanf": "fscanf",
    "__isoc99_scanf": "scanf",
    "__isoc99_sscanf": "sscanf",
    "__isoc99_vfscanf": "vfscanf",
    "__isoc99_vscanf": "vscanf",
    "__isoc99_vsscanf": "vsscanf",
    "__strtol_internal": "strtol",
    "__strtoll_internal": "strtoll",
    "__strtoul_internal": "strtoul",
    "__strtoull_internal": "strtoull",
    "__strtoimax_internal": "strtoimax",
    "__strtoumax_internal": "strtoumax",
}
_STRONG_WRAPPERS = ["__xmknod", "__xmknodat"]


def _fail(message: str) -> None:
    raise CompatibilityEntryAliasError(message)


def _load_contract(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _fail(f"cannot read compatibility-entry contract {path}: {error}")
    if not isinstance(value, dict) or set(value) != {
        "schema", "oracle", "weak_aliases", "strong_wrappers", "family_completion",
        "promotion_ready", "public_support",
    }:
        _fail("unexpected compatibility-entry contract shape")
    if value["schema"] != _SCHEMA or value["oracle"] != _ORACLE:
        _fail("wrong compatibility-entry schema or musl oracle")
    if value["weak_aliases"] != _WEAK_ALIASES or value["strong_wrappers"] != _STRONG_WRAPPERS:
        _fail("wrong compatibility-entry roster")
    if any(value[flag] is not False for flag in ("family_completion", "promotion_ready", "public_support")):
        _fail("compatibility-entry contract must remain non-promoting")
    return value


def parse_symbols(path: Path, *, archive: bool, table: str) -> list[dict[str, str]]:
    """Parse exactly one complete selected symbol table from ``readelf -W`` text."""

    if table not in {".dynsym", ".symtab"}:
        _fail(f"unsupported selected symbol table: {table}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        _fail(f"cannot read retained symbol text {path}: {error}")

    records: list[dict[str, str]] = []
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
        if expected_count is None:
            _fail(f"selected symbol table {table} has no declared count in {path}")
        if indexes != set(range(expected_count)):
            _fail(
                f"selected symbol table {table} in {path} is truncated or malformed: "
                f"declared {expected_count}, observed indexes {sorted(indexes)}"
            )
        selected_tables += 1
        current_table = None
        expected_count = None
        indexes = set()

    for raw in lines:
        if archive and raw.startswith("File: "):
            finish_table()
            current_file = raw[6:].strip()
            if not current_file:
                _fail(f"archive symbol table in {path} has an empty File: attribution")
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
            _fail(f"archive symbol row in {path} lacks a File: attribution")
        indexes.add(index)
        records.append(
            {
                "file": current_file,
                "table": table,
                "index": index_text,
                "value": value.lower(),
                "size": size,
                "type": kind,
                "binding": binding,
                "visibility": visibility,
                "section": section,
                "name": (name or "").split("@", 1)[0],
            }
        )
    finish_table()
    if selected_tables == 0:
        _fail(f"retained readelf text {path} has no {table} table")
    return records


def _defined(records: list[dict[str, str]], name: str) -> list[dict[str, str]]:
    return [record for record in records if record["name"] == name and record["section"] != "UND"]


def _one(records: list[dict[str, str]], name: str, where: str) -> dict[str, str]:
    choices = _defined(records, name)
    if len(choices) != 1:
        _fail(f"{where} requires exactly one defined {name}, found {len(choices)}")
    return choices[0]


def _metadata(record: dict[str, str], expected: tuple[str, str, str], where: str) -> None:
    observed = (record["type"], record["binding"], record["visibility"])
    if observed != expected:
        _fail(f"{where} metadata changed for {record['name']}: {observed}")


def _alias_pair(
    records: list[dict[str, str]], alias: str, target: str, *, archive: bool, where: str
) -> dict[str, dict[str, str]]:
    alias_record = _one(records, alias, where)
    target_record = _one(records, target, where)
    _metadata(alias_record, ("FUNC", "WEAK", "DEFAULT"), f"{where} weak alias")
    _metadata(target_record, ("FUNC", "GLOBAL", "DEFAULT"), f"{where} target")
    fields = ("value", "size", "section")
    if archive:
        fields = ("file",) + fields
    if any(alias_record[field] != target_record[field] for field in fields):
        _fail(f"{where} aliases are not one definition: {alias}/{target}")
    return {"alias": alias_record, "target": target_record}


def _wrapper(records: list[dict[str, str]], name: str, where: str) -> dict[str, str]:
    record = _one(records, name, where)
    _metadata(record, ("FUNC", "GLOBAL", "DEFAULT"), f"{where} wrapper")
    return record


def _validate_library(
    static: list[dict[str, str]], dynamic: list[dict[str, str]], shared: list[dict[str, str]],
    role: str,
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {"static": {}, "dynamic": {}, "shared_symtab": {}}
    for alias, target in _WEAK_ALIASES.items():
        result["static"][alias] = _alias_pair(static, alias, target, archive=True, where=f"{role} static")
        result["dynamic"][alias] = _alias_pair(dynamic, alias, target, archive=False, where=f"{role} dynamic")
        result["shared_symtab"][alias] = _alias_pair(
            shared, alias, target, archive=False, where=f"{role} shared symtab"
        )
    for wrapper in _STRONG_WRAPPERS:
        result["static"][wrapper] = _wrapper(static, wrapper, f"{role} static")
        result["dynamic"][wrapper] = _wrapper(dynamic, wrapper, f"{role} dynamic")
        result["shared_symtab"][wrapper] = _wrapper(shared, wrapper, f"{role} shared symtab")
    return result


def validate(
    contract_path: Path, oracle_static_path: Path, oracle_dynamic_path: Path, oracle_shared_path: Path,
    candidate_static_path: Path, candidate_dynamic_path: Path, candidate_shared_path: Path,
) -> dict[str, object]:
    """Replay exact symbol shapes without running a tool or consulting ambient files."""

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
        "oracle": _validate_library(oracle_static, oracle_dynamic, oracle_shared, "oracle"),
        "candidate": _validate_library(candidate_static, candidate_dynamic, candidate_shared, "candidate"),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 9:
        raise SystemExit(
            "usage: c_compatibility_entry_alias_symbols.py CONTRACT ORACLE_STATIC ORACLE_DYNAMIC "
            "ORACLE_SHARED CANDIDATE_STATIC CANDIDATE_DYNAMIC CANDIDATE_SHARED OUTPUT"
        )
    result = validate(*(Path(argument) for argument in argv[1:8]))
    Path(argv[8]).write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except CompatibilityEntryAliasError as error:
        raise SystemExit(f"compatibility-entry alias symbols: {error}")
