#!/usr/bin/env python3
"""Validate the selected musl locale/time alias shape from retained readelf text.

The installed-product runner deliberately records ``.dynsym`` and the full
``.symtab`` separately.  A full readelf dump contains both tables, and treating
their rows as one collection would make every exported symbol look like a
duplicate definition.  The time providers need the full table: their internal
spellings are intentionally local there while absent from ``.dynsym``.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Any


class LocaleAliasError(ValueError):
    """A retained locale/time alias observation does not match the contract."""


_TABLE_HEADER = re.compile(r"^Symbol table '([^']+)' contains ([0-9]+) entries:$")
_SYMBOL = re.compile(
    r"^\s*([0-9]+):\s+([0-9a-fA-F]+)\s+([0-9]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*?))?\s*$"
)


def _fail(message: str) -> None:
    raise LocaleAliasError(message)


def parse_symbols(path: Path, *, archive: bool, table: str) -> list[dict[str, str]]:
    """Parse exactly one named table from fixed ``readelf -W`` output.

    Every declared selected table must contain each index through its stated
    count.  Archive members retain their ``File:`` attribution.  The parser
    keeps index zero because a truncated table must not look like a valid empty
    export collection.
    """

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
        symbol_name = (name or "").split("@", 1)[0]
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
                "name": symbol_name,
            }
        )
    finish_table()
    if selected_tables == 0:
        _fail(f"retained readelf text {path} has no {table} table")
    return records


def _matching(records: list[dict[str, str]], name: str) -> list[dict[str, str]]:
    return [record for record in records if record["name"] == name and record["section"] != "UND"]


def _one(records: list[dict[str, str]], name: str, where: str) -> dict[str, str]:
    candidates = _matching(records, name)
    if len(candidates) != 1:
        _fail(f"{where} requires exactly one defined {name}, found {len(candidates)}")
    return candidates[0]


def _require_metadata(record: dict[str, str], expected: tuple[str, str, str], where: str) -> None:
    if (record["type"], record["binding"], record["visibility"]) != expected:
        _fail(f"{where} symbol metadata changed: {record['name']}")


def _same_definition(
    public: dict[str, str], internal: dict[str, str], fields: tuple[str, ...], where: str
) -> None:
    if any(public[field] != internal[field] for field in fields):
        _fail(f"{where} aliases are not the same definition: {public['name']}/{internal['name']}")


def _require_pair(
    records: list[dict[str, str]], public: str, internal: str, internal_visibility: str,
    where: str, archive: bool,
) -> dict[str, dict[str, str]]:
    public_record = _one(records, public, where)
    internal_record = _one(records, internal, where)
    _require_metadata(public_record, ("FUNC", "WEAK", "DEFAULT"), f"{where} public alias")
    _require_metadata(
        internal_record, ("FUNC", "GLOBAL", internal_visibility), f"{where} internal alias"
    )
    fields = ("value", "size", "section")
    if archive:
        fields = ("file",) + fields
    _same_definition(public_record, internal_record, fields, where)
    return {"public": public_record, "internal": internal_record}


def validate_shared_hidden_pair(
    records: list[dict[str, str]], public: str, internal: str, role: str
) -> dict[str, dict[str, str]]:
    """Require one hidden time implementation and its weak public alias in ``.symtab``."""

    if role not in {"oracle", "candidate"}:
        _fail(f"unsupported shared alias role: {role}")
    public_record = _one(records, public, f"{role} shared symtab")
    internal_record = _one(records, internal, f"{role} shared symtab")
    _require_metadata(public_record, ("FUNC", "WEAK", "DEFAULT"), f"{role} shared public alias")
    internal_visibility = "DEFAULT" if role == "oracle" else "HIDDEN"
    _require_metadata(
        internal_record, ("FUNC", "LOCAL", internal_visibility), f"{role} shared internal alias"
    )
    _same_definition(
        public_record,
        internal_record,
        ("value", "size", "section", "type"),
        f"{role} shared symtab",
    )
    return {"public": public_record, "internal": internal_record}


def _load_contract(path: Path) -> dict[str, Any]:
    try:
        contract = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _fail(f"cannot read locale alias contract {path}: {error}")
    if not isinstance(contract, dict) or set(contract) != {
        "schema", "oracle", "visible_aliases", "hidden_aliases", "file_local_aliases",
        "reverse_visible_aliases", "non_alias_locale_entries", "family_completion",
        "promotion_ready", "public_support",
    }:
        _fail("unexpected locale alias contract shape")
    if contract["schema"] != "crabc.x86_64-locale-alias-contract/v1":
        _fail("wrong locale alias contract schema")
    if contract["oracle"] != {
        "release": "musl-1.2.6",
        "revision": "9fa28ece75d8a2191de7c5bb53bed224c5947417",
    }:
        _fail("wrong locale alias oracle")
    if any(contract[flag] is not False for flag in ("family_completion", "promotion_ready", "public_support")):
        _fail("locale alias contract must remain non-promoting")
    visible = contract["visible_aliases"]
    hidden = contract["hidden_aliases"]
    if (
        not isinstance(visible, dict)
        or not isinstance(hidden, dict)
        or len(visible) != 43
        or len(hidden) != 4
        or set(visible) & set(hidden)
        or any(
            not isinstance(public, str)
            or not isinstance(internal, str)
            or internal != "__" + public
            for public, internal in {**visible, **hidden}.items()
        )
    ):
        _fail("invalid alias roster")
    if contract["file_local_aliases"] != {"tzset": "__tzset"}:
        _fail("wrong file-local alias roster")
    if contract["reverse_visible_aliases"] != {"freelocale": "__freelocale"}:
        _fail("wrong reverse visible alias roster")
    if contract["non_alias_locale_entries"] != ["wcscasecmp_l", "wcsncasecmp_l"]:
        _fail("wrong strong locale entry roster")
    return contract


def _validate_library(
    static: list[dict[str, str]], dynamic: list[dict[str, str]], shared_symtab: list[dict[str, str]],
    role: str, contract: dict[str, Any],
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {"static": {}, "dynamic": {}, "shared_symtab": {}}
    for public, internal in contract["visible_aliases"].items():
        result["static"][public] = _require_pair(
            static, public, internal, "DEFAULT", f"{role} static", True
        )
        result["dynamic"][public] = _require_pair(
            dynamic, public, internal, "DEFAULT", f"{role} dynamic", False
        )
    for public, internal in contract["hidden_aliases"].items():
        result["static"][public] = _require_pair(
            static, public, internal, "HIDDEN", f"{role} static", True
        )
        public_record = _one(dynamic, public, f"{role} dynamic")
        _require_metadata(
            public_record, ("FUNC", "WEAK", "DEFAULT"), f"{role} dynamic hidden-provider public alias"
        )
        if _matching(dynamic, internal):
            _fail(f"{role} dynamic leaks hidden internal spelling: {internal}")
        result["dynamic"][public] = {"public": public_record, "internal": None}
        result["shared_symtab"][public] = validate_shared_hidden_pair(
            shared_symtab, public, internal, role
        )
    for public, internal in contract["reverse_visible_aliases"].items():
        for where, records, archive in (
            (f"{role} static", static, True),
            (f"{role} dynamic", dynamic, False),
        ):
            public_record = _one(records, public, where)
            internal_record = _one(records, internal, where)
            _require_metadata(public_record, ("FUNC", "GLOBAL", "DEFAULT"), f"{where} reverse public")
            _require_metadata(internal_record, ("FUNC", "WEAK", "DEFAULT"), f"{where} reverse weak")
            fields = ("value", "size", "section")
            if archive:
                fields = ("file",) + fields
            _same_definition(public_record, internal_record, fields, where)
            result["static" if archive else "dynamic"][public] = {
                "public": public_record,
                "internal": internal_record,
            }
    for public, internal in contract["file_local_aliases"].items():
        static_public = _one(static, public, f"{role} static")
        dynamic_public = _one(dynamic, public, f"{role} dynamic")
        _require_metadata(static_public, ("FUNC", "WEAK", "DEFAULT"), f"{role} static file-local public")
        _require_metadata(dynamic_public, ("FUNC", "WEAK", "DEFAULT"), f"{role} dynamic file-local public")
        if role == "oracle":
            static_internal = _one(static, internal, f"{role} static")
            _require_metadata(
                static_internal, ("FUNC", "LOCAL", "DEFAULT"), f"{role} static file-local internal"
            )
            _same_definition(
                static_public,
                static_internal,
                ("file", "value", "size", "section"),
                f"{role} static file-local",
            )
            if _matching(dynamic, internal):
                _fail(f"{role} dynamic leaks local internal spelling: {internal}")
            result["static"][public] = {"public": static_public, "internal": static_internal}
        else:
            if _matching(static, internal) or _matching(dynamic, internal):
                _fail(f"{role} materializes non-contract local spelling: {internal}")
            result["static"][public] = {"public": static_public, "internal": None}
        result["dynamic"][public] = {"public": dynamic_public, "internal": None}
    for name in contract["non_alias_locale_entries"]:
        for where, records in ((f"{role} static", static), (f"{role} dynamic", dynamic)):
            record = _one(records, name, where)
            _require_metadata(record, ("FUNC", "GLOBAL", "DEFAULT"), f"{where} direct locale entry")
    return result


def _validate_executable(records: list[dict[str, str]], label: str) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for name in (
        "newlocale", "duplocale", "uselocale", "nl_langinfo", "nl_langinfo_l",
        "isalpha_l", "iswalpha_l", "strcasecmp_l", "strcoll_l", "strftime_l",
        "gmtime_r", "localtime_r", "asctime_r", "tzset",
    ):
        record = _one(records, name, label)
        _require_metadata(record, ("FUNC", "GLOBAL", "DEFAULT"), f"{label} application override")
        result[name] = record
    return result


def validate_observation(
    contract_path: Path,
    oracle_static_path: Path,
    oracle_dynamic_path: Path,
    oracle_shared_path: Path,
    candidate_static_path: Path,
    candidate_dynamic_path: Path,
    candidate_shared_path: Path,
    executable_pie_path: Path,
    executable_non_pie_path: Path,
) -> dict[str, object]:
    """Reconstruct the complete narrow alias observation from raw readelf streams."""

    contract = _load_contract(contract_path)
    oracle_static = parse_symbols(oracle_static_path, archive=True, table=".symtab")
    oracle_dynamic = parse_symbols(oracle_dynamic_path, archive=False, table=".dynsym")
    oracle_shared = parse_symbols(oracle_shared_path, archive=False, table=".symtab")
    candidate_static = parse_symbols(candidate_static_path, archive=True, table=".symtab")
    candidate_dynamic = parse_symbols(candidate_dynamic_path, archive=False, table=".dynsym")
    candidate_shared = parse_symbols(candidate_shared_path, archive=False, table=".symtab")
    executable_pie = parse_symbols(executable_pie_path, archive=False, table=".dynsym")
    executable_non_pie = parse_symbols(executable_non_pie_path, archive=False, table=".dynsym")
    if not all(
        (
            oracle_static,
            oracle_dynamic,
            oracle_shared,
            candidate_static,
            candidate_dynamic,
            candidate_shared,
            executable_pie,
            executable_non_pie,
        )
    ):
        _fail("missing parsable ELF symbol records")
    return {
        "oracle": _validate_library(oracle_static, oracle_dynamic, oracle_shared, "oracle", contract),
        "candidate": _validate_library(
            candidate_static, candidate_dynamic, candidate_shared, "candidate", contract
        ),
        "executables": {
            "dynamic-pie": _validate_executable(executable_pie, "dynamic-pie executable"),
            "dynamic-non-pie": _validate_executable(
                executable_non_pie, "dynamic-non-pie executable"
            ),
        },
    }


def main(argv: list[str]) -> int:
    if len(argv) != 10:
        raise LocaleAliasError(
            "usage: locale_alias_contract_symbols.py CONTRACT ORACLE_STATIC ORACLE_DYNSYM "
            "ORACLE_SYMTAB CANDIDATE_STATIC CANDIDATE_DYNSYM CANDIDATE_SYMTAB "
            "EXECUTABLE_PIE EXECUTABLE_NON_PIE OUTPUT"
        )
    paths = [Path(value) for value in argv]
    observation = validate_observation(*paths[:-1])
    try:
        paths[-1].write_text(
            json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
    except OSError as error:
        raise LocaleAliasError(f"cannot write alias observation {paths[-1]}: {error}") from error
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except LocaleAliasError as error:
        print(f"locale alias symbol contract: {error}", file=sys.stderr)
        raise SystemExit(1)
