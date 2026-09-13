#!/usr/bin/env python3
"""Collect finite native C/C++ declaration-emission and record-layout facts.

The header declaration inventory owns raw compiler collection.  This companion
uses that already replayed envelope to generate ordinary object files from the
actual direct header declarations.  It does not synthesize declarations,
choose an archive provider, or turn declaration evidence into runtime or
family completion.
"""
from __future__ import annotations

import argparse
from collections import Counter
import concurrent.futures
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tomllib
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MODULE_DIRECTORY = Path(__file__).resolve().parent
if str(MODULE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(MODULE_DIRECTORY))

import header_record_layout_matrix as record_layout_matrix
import header_abi_matrix as header_abi_matrix
import header_callable_disposition as callable_disposition
import header_callable_inventory as callable_inventory
import header_declaration_inventory as declaration_inventory
import feature_archive_roster as feature_archive_roster
import native_abi_inventory as abi_inventory
import native_callable_declarations as callable_declarations


SCHEMA = "crabc.x86_64-native-declaration-abi/v1"
RECORD_LAYOUT_PROJECTION_SCHEMA = "crabc.x86_64-native-declaration-record-layout-projection/v1"
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "native_declaration_abi.toml"
TARGET = "x86_64-unknown-linux-musl"
ORACLE = "Pinned musl 1.2.6"
IMAGE_ENV = "CRABC_X86_DECLARATION_ABI_IMAGE_ID"
IMAGE_PATTERN = re.compile(r"crabc-core-evidence@sha256:[0-9a-f]{64}")
SOURCE_MOUNT = Path("/workspace")
WORK_DIRECTORY = ROOT / ".work" / "x86_64" / "native-declaration-abi"
DEFAULT_TIMEOUT_SECONDS = 120.0
DEFAULT_WORKERS = 8
MAX_WORKERS = 16
HEADER_DECLARATION_REPORT_SCHEMA = "crabc.x86_64-header-declaration-inventory/v1"
HEADER_ABI_MATRIX_REPORT_SCHEMA = "crabc.x86_64-header-abi-matrix-report/v2"
HEADER_RECORD_LAYOUT_REPORT_SCHEMA = "crabc.x86_64-header-record-layout-matrix-report/v1"
PROFILE_LANGUAGES = dict(callable_declarations.PROFILE_LANGUAGES)
SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SYMBOL_ROW = re.compile(
    r"^\s*(?P<index>[0-9]+):\s+(?P<value>[0-9A-Fa-f]+)\s+(?P<size>[0-9]+)\s+"
    r"(?P<type>\S+)\s+(?P<binding>\S+)\s+(?P<visibility>\S+)\s+(?P<section>\S+)\s*(?P<name>.*)$"
)
SYMBOL_TABLE = re.compile(r"^Symbol table '(?P<name>[^']+)' contains (?P<count>[0-9]+) entr(?:y|ies):$")
SYMBOL_COLUMNS = "Num: Value Size Type Bind Vis Ndx Name".split()
RELOCATION_ROW = re.compile(
    r"^\s*[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(?P<type>R_X86_64_[A-Za-z0-9_]+)\s+"
    r"[0-9A-Fa-f]+\s+(?P<symbol>\S+)(?:\s+[+-]\s+[0-9]+)?\s*$"
)
RELOCATION_TABLE = re.compile(
    r"^Relocation section '(?P<name>[^']+)' at offset 0x[0-9A-Fa-f]+ contains (?P<count>[0-9]+) entr(?:y|ies):$"
)
NO_RELOCATIONS = "There are no relocations in this file."

LAYOUT_FACTS = (
    {
        "header": "arpa/nameser.h",
        "object_names": ("_ns_flagdata",),
        "profiles": tuple(PROFILE_LANGUAGES),
        "record": "_ns_flagdata",
    },
    {
        "header": "netinet/in.h",
        "object_names": ("in6addr_any", "in6addr_loopback"),
        "profiles": tuple(PROFILE_LANGUAGES),
        "record": "in6_addr",
    },
)
LIMITS = {
    "FILE": "opaque-or-incomplete-not-proved",
    "_IO_FILE": "opaque-or-incomplete-not-proved",
    "_ns_flagdata_array_extent": "not-proved-by-record-layout",
    "h_errno_accessor_storage": "runtime-semantic-owner-required",
}
POLICY = {
    "actual_header_declarations_only": True,
    "archive_provider_selection": False,
    "c_and_cxx_object_emission": True,
    "header_replay_owned_elsewhere": True,
    "header_runtime_semantics": False,
    "mangled_name_is_not_linkage_proof": True,
    "record_layout_projection_only": True,
    "runtime_family_completion": False,
}


class NativeDeclarationAbiError(ValueError):
    """The finite declaration ABI evidence is malformed or inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeDeclarationAbiError(message)


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def strict_equal(left: object, right: object) -> bool:
    return canonical_json(left) == canonical_json(right)


def sha256_file(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"unsafe regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json_object(path: Path, description: str) -> dict[str, Any]:
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), f"{description} is not a physical regular file")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            require(key not in result, f"{description} has a duplicate JSON key")
            result[key] = value
        return result

    def finite_float(token: str) -> float:
        value = float(token)
        require(math.isfinite(value), f"{description} contains a non-finite number")
        return value

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=pairs,
            parse_float=finite_float,
            parse_constant=lambda token: (_ for _ in ()).throw(
                NativeDeclarationAbiError(f"{description} contains a non-JSON number {token}")
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDeclarationAbiError(f"cannot read {description}: {error}") from error
    require(type(value) is dict, f"{description} is not a JSON object")
    return value


def _read_json_value(path: Path, description: str, expected_type: type[Any]) -> Any:
    """Read one finite retained JSON value with duplicate-key rejection."""
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), f"{description} is not a physical regular file")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            require(key not in result, f"{description} has a duplicate JSON key")
            result[key] = value
        return result

    def finite_float(token: str) -> float:
        value = float(token)
        require(math.isfinite(value), f"{description} contains a non-finite number")
        return value

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=pairs,
            parse_float=finite_float,
            parse_constant=lambda token: (_ for _ in ()).throw(
                NativeDeclarationAbiError(f"{description} contains a non-JSON number {token}")
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDeclarationAbiError(f"cannot read {description}: {error}") from error
    require(type(value) is expected_type, f"{description} is not a {expected_type.__name__}")
    return value


def _safe_relative(value: object, description: str) -> str:
    require(type(value) is str and bool(value), f"{description} is not a nonempty string")
    path = Path(value)
    require(not path.is_absolute() and ".." not in path.parts and path.as_posix() == value, f"{description} is not a safe relative path")
    return value


def _symbol(value: object, description: str) -> str:
    require(type(value) is str and SYMBOL.fullmatch(value) is not None, f"{description} is not a C identifier")
    return value


def _load_toml(path: Path) -> Mapping[str, Any]:
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise NativeDeclarationAbiError(f"cannot load declaration ABI contract {path}: {error}") from error
    require(isinstance(value, Mapping), "declaration ABI contract is not a table")
    return value


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    """Load the small reviewed declaration ABI boundary exactly."""
    raw = _load_toml(path)
    expected = {
        "schema",
        "target",
        "oracle",
        "header_declaration_report_schema",
        "header_abi_matrix_report_schema",
        "header_record_layout_matrix_report_schema",
        "profile_languages",
        "policy",
        "record_layout",
        "limits",
    }
    require(set(raw) == expected, "declaration ABI contract fields differ")
    require(raw["schema"] == SCHEMA, "declaration ABI contract schema differs")
    require(raw["target"] == TARGET and raw["oracle"] == ORACLE, "declaration ABI contract identity differs")
    require(raw["header_declaration_report_schema"] == HEADER_DECLARATION_REPORT_SCHEMA, "declaration ABI header report schema differs")
    require(raw["header_abi_matrix_report_schema"] == HEADER_ABI_MATRIX_REPORT_SCHEMA, "declaration ABI header matrix schema differs")
    require(raw["header_record_layout_matrix_report_schema"] == HEADER_RECORD_LAYOUT_REPORT_SCHEMA, "declaration ABI layout matrix schema differs")
    require(isinstance(raw["profile_languages"], Mapping) and dict(raw["profile_languages"]) == PROFILE_LANGUAGES,
            "declaration ABI profile language mapping differs")
    require(isinstance(raw["policy"], Mapping) and set(raw["policy"]) == set(POLICY), "declaration ABI policy fields differ")
    for key, expected_value in POLICY.items():
        require(type(raw["policy"][key]) is bool and raw["policy"][key] is expected_value,
                f"declaration ABI policy.{key} differs")
    raw_facts = raw["record_layout"]
    require(isinstance(raw_facts, list) and len(raw_facts) == len(LAYOUT_FACTS), "declaration ABI layout fact roster differs")
    facts: list[dict[str, Any]] = []
    for index, (item, expected_fact) in enumerate(zip(raw_facts, LAYOUT_FACTS, strict=True)):
        require(isinstance(item, Mapping) and set(item) == {"header", "object_names", "profiles", "record"},
                f"declaration ABI layout fact {index} fields differ")
        header = _safe_relative(item["header"], f"declaration ABI layout fact {index}.header")
        record = _symbol(item["record"], f"declaration ABI layout fact {index}.record")
        objects = item["object_names"]
        profiles = item["profiles"]
        require(isinstance(objects, list) and tuple(objects) == expected_fact["object_names"],
                f"declaration ABI layout fact {index}.object_names differs")
        require(isinstance(profiles, list) and tuple(profiles) == expected_fact["profiles"],
                f"declaration ABI layout fact {index}.profiles differs")
        require(header == expected_fact["header"] and record == expected_fact["record"],
                f"declaration ABI layout fact {index} differs")
        facts.append({"header": header, "object_names": list(objects), "profiles": list(profiles), "record": record})
    require(isinstance(raw["limits"], Mapping) and dict(raw["limits"]) == LIMITS, "declaration ABI limits differ")
    return {
        "schema": SCHEMA,
        "target": TARGET,
        "oracle": ORACLE,
        "header_declaration_report_schema": HEADER_DECLARATION_REPORT_SCHEMA,
        "header_abi_matrix_report_schema": HEADER_ABI_MATRIX_REPORT_SCHEMA,
        "header_record_layout_matrix_report_schema": HEADER_RECORD_LAYOUT_REPORT_SCHEMA,
        "profile_languages": dict(PROFILE_LANGUAGES),
        "policy": dict(POLICY),
        "record_layout": facts,
        "limits": dict(LIMITS),
    }


def _reviewed_contract(contract: Mapping[str, Any] | None) -> dict[str, Any]:
    canonical = load_contract()
    if contract is not None:
        require(isinstance(contract, Mapping) and strict_equal(contract, canonical),
                "supplied declaration ABI contract differs from reviewed canonical contract")
    return canonical


def _record_named(records: object, name: str, description: str) -> dict[str, Any]:
    require(isinstance(records, list), f"{description} records are invalid")
    matches = [record for record in records if isinstance(record, Mapping) and record.get("name") == name]
    require(len(matches) == 1, f"{description} record {name} is absent or duplicated")
    return copy.deepcopy(dict(matches[0]))


def project_checked_record_layout(
    report: Mapping[str, Any],
    *,
    contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project only selected named record facts from the checked matrix.

    The matrix reader remains responsible for the full 1,337-row roster.  This
    projection deliberately has no authority over incomplete ``FILE`` types or
    an array provider's storage extent.
    """
    selected = _reviewed_contract(contract)
    try:
        record_layout_matrix.validate_checked_report(report)
    except (ValueError, OSError) as error:
        raise NativeDeclarationAbiError(f"checked record-layout matrix rejected: {error}") from error
    require(report.get("schema") == HEADER_RECORD_LAYOUT_REPORT_SCHEMA, "checked record-layout matrix schema differs")
    raw_rows = report.get("rows")
    require(isinstance(raw_rows, list), "checked record-layout rows are invalid")
    rows: dict[tuple[str, str], Mapping[str, Any]] = {}
    for raw in raw_rows:
        require(isinstance(raw, Mapping), "checked record-layout row is invalid")
        header = _safe_relative(raw.get("header"), "checked record-layout header")
        profile = raw.get("profile")
        require(type(profile) is str and profile in PROFILE_LANGUAGES, "checked record-layout profile is invalid")
        key = (header, profile)
        require(key not in rows, "checked record-layout row repeats")
        rows[key] = raw
    projected: list[dict[str, Any]] = []
    for fact in selected["record_layout"]:
        profiles: list[dict[str, Any]] = []
        for profile in fact["profiles"]:
            row = rows.get((fact["header"], profile))
            require(row is not None, f"checked record-layout row is absent: {fact['header']}:{profile}")
            require(row.get("comparison") == "matched" and row.get("candidate_status") == "ok"
                    and row.get("reference_status") == "ok", f"selected record layout is not matched: {fact['record']}:{profile}")
            candidate = _record_named(row.get("candidate_records"), fact["record"], f"candidate {fact['header']}:{profile}")
            reference = _record_named(row.get("reference_records"), fact["record"], f"reference {fact['header']}:{profile}")
            require(candidate.get("applicability") == "applicable" and reference.get("applicability") == "applicable",
                    f"selected record layout is incomplete: {fact['record']}:{profile}")
            difference = record_layout_matrix.compare_records([candidate], [reference])
            require(
                difference["candidate_only_count"] == 0
                and difference["reference_only_count"] == 0
                and difference["incompatible_count"] == 0,
                f"selected record layout differs: {fact['record']}:{profile}",
            )
            profiles.append({"candidate": candidate, "profile": profile, "reference": reference})
        projected.append(
            {
                "header": fact["header"],
                "object_names": list(fact["object_names"]),
                "profiles": profiles,
                "record": fact["record"],
            }
        )
    return {
        "schema": RECORD_LAYOUT_PROJECTION_SCHEMA,
        "record_layout_report_schema": HEADER_RECORD_LAYOUT_REPORT_SCHEMA,
        "records": projected,
        "limits": copy.deepcopy(selected["limits"]),
    }


def _source_definition_observations(observations: object, description: str) -> list[str]:
    require(isinstance(observations, list) and bool(observations), f"{description} observations are absent")
    values: list[str] = []
    signatures: set[tuple[object, object]] = set()
    for index, raw in enumerate(observations):
        require(isinstance(raw, Mapping), f"{description} observation {index} is invalid")
        name = _symbol(raw.get("name"), f"{description} observation {index}.name")
        definition = raw.get("definition_observation")
        require(type(definition) is str and bool(definition), f"{description} observation {index}.definition differs")
        mangled = raw.get("mangled_name_observation")
        require(type(mangled) is str and bool(mangled), f"{description} observation {index}.mangled name differs")
        source = raw.get("source")
        require(isinstance(source, Mapping), f"{description} observation {index}.source differs")
        _safe_relative(source.get("declaring_header"), f"{description} observation {index}.declaring header")
        signatures.add((raw.get("type", {}).get("qual_type") if isinstance(raw.get("type"), Mapping) else None, mangled))
        values.append(definition)
        require(name, "unreachable selected callable name")
    require(len(signatures) == 1, f"{description} has ambiguous direct declaration signatures")
    return sorted(set(values))


def linkage_jobs_from_callable_account(account: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Create one source plan per observed direct tree/header/profile job.

    The caller supplies the already authenticated callable account.  A direct
    name with multiple type/mangled spellings is rejected before any source is
    generated; guessing a cast or a linker name would hide the declaration
    defect this component is meant to observe.
    """
    require(isinstance(account, Mapping), "callable declaration account is invalid")
    groups = account.get("groups")
    require(isinstance(groups, list) and bool(groups), "callable declaration groups are absent")
    jobs: dict[tuple[str, str, str], dict[str, Any]] = {}
    for index, raw in enumerate(groups):
        require(isinstance(raw, Mapping), f"callable declaration group {index} is invalid")
        category = raw.get("category")
        require(category in {
                    "reference-backed",
                    "reviewed-native-extension",
                    "candidate-project-extension",
                    "oracle-not-applicable",
                },
                f"callable declaration group {index}.category is invalid")
        header = _safe_relative(raw.get("input_header"), f"callable declaration group {index}.header")
        profile = raw.get("profile")
        require(type(profile) is str and profile in PROFILE_LANGUAGES, f"callable declaration group {index}.profile is invalid")
        name = _symbol(raw.get("name"), f"callable declaration group {index}.name")
        candidate = raw.get("candidate_observations")
        reference = raw.get("reference_observations")
        candidate_definitions = _source_definition_observations(candidate, f"candidate callable declaration {header}:{profile}:{name}")
        if category == "reference-backed":
            reference_definitions = _source_definition_observations(reference, f"reference callable declaration {header}:{profile}:{name}")
        else:
            require(reference == [], f"candidate-only callable declaration unexpectedly has reference observations: {header}:{profile}:{name}")
            reference_definitions = []
        for tree, definitions in (("candidate", candidate_definitions), ("reference", reference_definitions)):
            if not definitions:
                continue
            key = (tree, header, profile)
            job = jobs.setdefault(
                key,
                {
                    "tree": tree,
                    "header": header,
                    "profile": profile,
                    "language": PROFILE_LANGUAGES[profile],
                    "names": [],
                    "references": [],
                },
            )
            require(name not in job["names"], f"callable declaration job duplicates {name}: {tree}:{header}:{profile}")
            job["names"].append(name)
            job["references"].append(
                {
                    "category": category,
                    "name": name,
                    "source_definition_observations": definitions,
                    "expected_observation": (
                        "header-defined-or-inline" if "function-body-present" in definitions else "ordinary-undefined-reference"
                    ),
                }
            )
    result: list[dict[str, Any]] = []
    for key in sorted(jobs):
        job = jobs[key]
        pairs = sorted(zip(job["names"], job["references"], strict=True), key=lambda pair: pair[0])
        job["names"] = [name for name, _ in pairs]
        job["references"] = [
            {
                **record,
                # This source-local label gives every address reference an
                # object-level relocation domain.  It is deliberately not a
                # declaration or provider spelling: the relocation target is
                # the emitted linker identity we are measuring.
                "holder": f"crabc_native_declaration_abi_reference_{index}",
            }
            for index, (_name, record) in enumerate(pairs)
        ]
        result.append(job)
    require(bool(result), "callable declaration linkage plan is empty")
    return result


def generated_source(plan: Mapping[str, Any]) -> str:
    """Render one address-taking source file without declaring a callable."""
    require(isinstance(plan, Mapping), "linkage source plan is invalid")
    header = _safe_relative(plan.get("header"), "linkage source header")
    language = plan.get("language")
    require(language in {"c", "cxx"}, "linkage source language is invalid")
    names = plan.get("names")
    references = plan.get("references")
    require(isinstance(names, list) and names == sorted(names) and bool(names), "linkage source names are invalid")
    require(isinstance(references, list) and len(references) == len(names), "linkage source references are invalid")
    rendered = [f"#include <{header}>", ""]
    for index, (raw_name, raw_reference) in enumerate(zip(names, references, strict=True)):
        name = _symbol(raw_name, f"linkage source name {index}")
        require(isinstance(raw_reference, Mapping) and raw_reference.get("name") == name,
                f"linkage source reference name differs: {name}")
        holder = _symbol(raw_reference.get("holder"), f"linkage source holder {index}")
        require(holder == f"crabc_native_declaration_abi_reference_{index}",
                f"linkage source holder differs: {name}")
        rendered.append(
            f"static __typeof__(&{name}) volatile {holder} __asm__(\"{holder}\") "
            f"__attribute__((used)) = &{name};"
        )
    rendered.append("")
    return "\n".join(rendered)


def parse_symbol_table(text: str) -> list[dict[str, Any]]:
    """Parse retained x86 object symbol rows without treating text as a link result."""
    require(type(text) is str, "symbol-table output is not text")
    tables: list[tuple[str, int, list[dict[str, Any]]]] = []
    current_name: str | None = None
    current_count: int | None = None
    current_rows: list[dict[str, Any]] | None = None
    saw_columns = False

    def finish() -> None:
        nonlocal current_name, current_count, current_rows, saw_columns
        if current_name is None:
            return
        require(saw_columns, f"symbol table {current_name} lacks its column header")
        require(current_rows is not None and current_count is not None, "symbol table parser state is invalid")
        require(len(current_rows) == current_count, f"symbol table {current_name} is truncated or has extra rows")
        require([row["index"] for row in current_rows] == list(range(current_count)),
                f"symbol table {current_name} rows are missing or reordered")
        tables.append((current_name, current_count, current_rows))
        current_name = None
        current_count = None
        current_rows = None
        saw_columns = False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        table = SYMBOL_TABLE.fullmatch(stripped)
        if table is not None:
            finish()
            current_name = table.group("name")
            current_count = int(table.group("count"), 10)
            current_rows = []
            saw_columns = False
            continue
        require(current_name is not None, f"symbol-table output precedes a table: {line}")
        if stripped.split() == SYMBOL_COLUMNS:
            require(not saw_columns and current_rows == [], f"symbol table {current_name} has duplicate column header")
            saw_columns = True
            continue
        require(saw_columns and current_rows is not None, f"symbol table {current_name} lacks its column header")
        match = SYMBOL_ROW.fullmatch(line)
        require(match is not None, f"symbol table {current_name} has malformed row: {line}")
        name = match.group("name").strip()
        row = (
            {
                "binding": match.group("binding"),
                "index": int(match.group("index"), 10),
                "name": name,
                "section": match.group("section"),
                "size": int(match.group("size"), 10),
                "type": match.group("type"),
                "value": match.group("value").lower(),
                "visibility": match.group("visibility"),
            }
        )
        require(row["index"] == len(current_rows), f"symbol table {current_name} row index differs")
        current_rows.append(row)
    finish()
    require(len(tables) == 1 and tables[0][0] == ".symtab", "object symbol-table roster differs")
    result = tables[0][2]
    require(bool(result), "symbol-table output has no rows")
    return result


def parse_relocations(text: str) -> list[dict[str, str]]:
    """Parse retained x86 relocation identities used by address references."""
    require(type(text) is str, "relocation output is not text")
    require(text.endswith("\n"), "relocation output is not newline terminated")
    if text == NO_RELOCATIONS + "\n":
        return []
    tables: list[tuple[str, int, list[dict[str, str]]]] = []
    current_name: str | None = None
    current_count: int | None = None
    current_rows: list[dict[str, str]] | None = None
    saw_columns = False

    def finish() -> None:
        nonlocal current_name, current_count, current_rows, saw_columns
        if current_name is None:
            return
        require(saw_columns, f"relocation table {current_name} lacks its column header")
        require(current_rows is not None and current_count is not None, "relocation table parser state is invalid")
        require(len(current_rows) == current_count, f"relocation table {current_name} is truncated or has extra rows")
        tables.append((current_name, current_count, current_rows))
        current_name = None
        current_count = None
        current_rows = None
        saw_columns = False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        table = RELOCATION_TABLE.fullmatch(stripped)
        if table is not None:
            finish()
            current_name = table.group("name")
            current_count = int(table.group("count"), 10)
            current_rows = []
            saw_columns = False
            continue
        require(current_name is not None, f"relocation output precedes a table: {line}")
        if stripped.startswith("Offset"):
            require(not saw_columns and current_rows == [], f"relocation table {current_name} has duplicate column header")
            saw_columns = True
            continue
        require(saw_columns and current_rows is not None, f"relocation table {current_name} lacks its column header")
        match = RELOCATION_ROW.fullmatch(line)
        require(match is not None, f"relocation table {current_name} has malformed row: {line}")
        current_rows.append(
            {
                "section": current_name,
                "symbol": match.group("symbol"),
                "type": match.group("type"),
            }
        )
    finish()
    require(bool(tables), "relocation output has no relocation table")
    result: list[dict[str, str]] = []
    for _name, _count, rows in tables:
        result.extend(rows)
    return result


def evaluate_object_linkage(
    plan: Mapping[str, Any],
    symbols: Sequence[Mapping[str, Any]],
    relocations: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Classify each source-derived address reference from real object facts."""
    require(isinstance(plan, Mapping), "linkage plan is invalid")
    references = plan.get("references")
    require(isinstance(references, list) and bool(references), "linkage plan references are absent")
    require(isinstance(symbols, Sequence) and not isinstance(symbols, (str, bytes)), "object symbol rows are invalid")
    require(isinstance(relocations, Sequence) and not isinstance(relocations, (str, bytes)), "object relocation rows are invalid")
    result: list[dict[str, Any]] = []
    for raw in references:
        require(isinstance(raw, Mapping), "linkage reference is invalid")
        name = _symbol(raw.get("name"), "linkage reference name")
        holder = _symbol(raw.get("holder"), f"linkage reference holder: {name}")
        category = raw.get("category")
        require(category in {
                    "reference-backed",
                    "reviewed-native-extension",
                    "candidate-project-extension",
                    "oracle-not-applicable",
                }, f"linkage reference category is invalid for {name}")
        expected = raw.get("expected_observation")
        definitions = raw.get("source_definition_observations")
        require(isinstance(definitions, list) and definitions == sorted(set(definitions)) and bool(definitions),
                f"linkage reference definitions are invalid: {name}")
        matching = [dict(row) for row in symbols if isinstance(row, Mapping) and row.get("name") == name]
        if expected == "ordinary-undefined-reference":
            table = f".rela.data.{holder}"
            referenced = [row for row in relocations if isinstance(row, Mapping) and row.get("section") == table]
            require(len(referenced) == 1, f"ordinary object has no unambiguous retained relocation for {name}")
            relocation = referenced[0]
            observed_name = _symbol(relocation.get("symbol"), f"ordinary relocation symbol: {name}")
            observed_rows = [
                row
                for row in symbols
                if isinstance(row, Mapping) and row.get("name") == observed_name and row.get("section") == "UND"
            ]
            require(len(observed_rows) == 1, f"ordinary object undefined symbol roster differs for {name}")
            row = observed_rows[0]
            require(row.get("binding") == "GLOBAL" and row.get("visibility") == "DEFAULT",
                    f"ordinary undefined reference metadata differs for {name}")
            relocation_type = _string(relocation.get("type"), f"ordinary relocation type: {name}")
            if observed_name == name:
                result.append({
                    "category": category,
                    "name": name,
                    "status": "ordinary-undefined-reference",
                    "symbol": name,
                })
            else:
                # C++ headers lacking C language linkage are a real output
                # observation.  Retain their emitted target instead of
                # recovering a spelling from the AST or treating the entire
                # collection as a synthetic compiler failure.
                result.append(
                    {
                        "category": category,
                        "expected_symbol": name,
                        "holder": holder,
                        "observed_symbol": observed_name,
                        "relocation_type": relocation_type,
                        "status": "ordinary-linkage-identity-mismatch",
                    }
                )
        elif expected == "header-defined-or-inline":
            require("function-body-present" in definitions, f"header-defined classification lacks source evidence for {name}")
            defined = [row for row in matching if row.get("section") not in {None, "UND"}]
            require(bool(defined), f"ordinary object lacks its source-defined callable observation for {name}")
            result.append(
                {
                    "category": category,
                    "name": name,
                    "source_definition_observation": "function-body-present",
                    "status": "header-defined-or-inline",
                }
            )
        else:
            raise NativeDeclarationAbiError(f"linkage reference observation is invalid for {name}")
    return result


# The declaration inventory retains the complete compiler/header envelope.
# These are the smaller current-source inputs which turn that envelope into a
# finite ordinary-object plan.  Keep this list explicit: adding a helper or a
# contract to the collector requires adding its bytes here rather than
# silently trusting the checkout at replay time.
SOURCE_FILES = (
    "compat/x86_64/native_declaration_abi.py",
    "compat/x86_64/native_declaration_abi.toml",
    "compat/x86_64/header_declaration_inventory.py",
    "compat/x86_64/header_callable_inventory.py",
    "compat/x86_64/header_callable_inventory.toml",
    "compat/x86_64/header_callable_disposition.py",
    "compat/x86_64/header_callable_disposition.toml",
    "compat/x86_64/header_callable_disposition.json",
    "compat/x86_64/header_callable_linkage_audit.py",
    "compat/x86_64/header_callable_extension_contract.py",
    "compat/x86_64/header_callable_extension_contract.toml",
    "compat/x86_64/header_abi_matrix.py",
    "compat/x86_64/header_abi_matrix.toml",
    "compat/x86_64/generated/header_abi_matrix/report.json",
    "compat/x86_64/header_record_layout_matrix.py",
    "compat/x86_64/header_record_layout_matrix.toml",
    "compat/x86_64/generated/header_record_layout_matrix/report.json",
    "compat/x86_64/native_data_declarations.py",
    "compat/x86_64/native_callable_declarations.py",
    "compat/x86_64/native_callable_declarations.toml",
    "compat/x86_64/feature_archive_roster.py",
    "compat/x86_64/native_abi_inventory.py",
    "compat/x86_64/owned_posix_product_evidence.py",
    "compat/x86_64/owned_dynamic_qualification.py",
    "compat/x86_64/owned_dynamic_receipt.py",
    "compat/x86_64/dynamic_product_contract.py",
    "compat/x86_64/crabc_cc_owned_dynamic.py",
    "compat/x86_64/crabc_cc_static.py",
    "compat/x86_64/owned_loader_corpus_evidence.py",
    "compat/x86_64/validate_loader_libc_tls_runtime_v1.py",
    "compat/x86_64/static_c_abi_exports.txt",
    "compat/x86_64/parity.toml",
    "libc/Cargo.toml",
)


def _exact_keys(value: object, keys: set[str], description: str) -> Mapping[str, Any]:
    require(isinstance(value, Mapping) and set(value) == keys, f"{description} fields differ")
    return value


def _string(value: object, description: str, *, empty: bool = False) -> str:
    require(type(value) is str and (empty or bool(value)), f"{description} is not a string")
    return value


def _nonnegative_integer(value: object, description: str) -> int:
    require(type(value) is int and value >= 0, f"{description} is not a nonnegative integer")
    return value


def _positive_integer(value: object, description: str) -> int:
    require(type(value) is int and value > 0, f"{description} is not a positive integer")
    return value


def _boolean(value: object, description: str) -> bool:
    require(type(value) is bool, f"{description} is not Boolean")
    return value


def _physical_path(path: Path, description: str, *, directory: bool | None = None) -> Path:
    supplied = Path(path)
    absolute = supplied if supplied.is_absolute() else ROOT / supplied
    absolute = absolute.absolute()
    try:
        resolved = absolute.resolve(strict=True)
        details = absolute.lstat()
    except OSError as error:
        raise NativeDeclarationAbiError(f"cannot inspect {description}: {absolute}") from error
    require(resolved == absolute and not stat.S_ISLNK(details.st_mode), f"{description} is not physical: {absolute}")
    if directory is True:
        require(stat.S_ISDIR(details.st_mode), f"{description} is not a directory: {absolute}")
    elif directory is False:
        require(stat.S_ISREG(details.st_mode), f"{description} is not a regular file: {absolute}")
    return absolute


def _physical_new_output(path: Path) -> Path:
    supplied = Path(path)
    output = supplied if supplied.is_absolute() else ROOT / supplied
    output = output.absolute()
    require(output.parent == WORK_DIRECTORY, "declaration ABI output is not an immediate native work-directory child")
    WORK_DIRECTORY.mkdir(parents=True, exist_ok=True)
    _physical_path(WORK_DIRECTORY, "native declaration ABI work directory", directory=True)
    require(not output.exists() and not output.is_symlink(), "declaration ABI output must be fresh")
    return output


def _source_identity(path: Path, description: str) -> dict[str, Any]:
    physical = _physical_path(path, description, directory=False)
    require(physical.is_relative_to(ROOT), f"{description} escapes the checkout")
    details = physical.stat()
    return {
        "mode": stat.S_IMODE(details.st_mode),
        "path": physical.relative_to(ROOT).as_posix(),
        "sha256": sha256_file(physical),
        "size": details.st_size,
    }


def _artifact_identity(output: Path, path: Path, description: str) -> dict[str, Any]:
    output = _physical_path(output, "declaration ABI evidence directory", directory=True)
    physical = _physical_path(path, description, directory=False)
    require(physical.is_relative_to(output), f"{description} escapes declaration ABI evidence")
    details = physical.stat()
    return {
        "mode": stat.S_IMODE(details.st_mode),
        "path": physical.relative_to(output).as_posix(),
        "sha256": sha256_file(physical),
        "size": details.st_size,
    }


def _validate_artifact_descriptor(output: Path, value: object, description: str) -> dict[str, Any]:
    record = _exact_keys(value, {"mode", "path", "sha256", "size"}, description)
    path = _safe_relative(record["path"], f"{description}.path")
    digest = _string(record["sha256"], f"{description}.sha256")
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"{description}.sha256 is invalid")
    _nonnegative_integer(record["size"], f"{description}.size")
    _nonnegative_integer(record["mode"], f"{description}.mode")
    actual = _artifact_identity(output, output / path, description)
    require(strict_equal(record, actual), f"{description} bytes differ")
    return actual


def _external_identity(path: Path, description: str) -> dict[str, Any]:
    physical = _physical_path(path, description, directory=False)
    details = physical.stat()
    return {
        "mode": stat.S_IMODE(details.st_mode),
        "path": str(physical),
        "sha256": sha256_file(physical),
        "size": details.st_size,
    }


def _validate_external_identity(value: object, path: Path, description: str) -> dict[str, Any]:
    raw = _exact_keys(value, {"mode", "path", "sha256", "size"}, description)
    collector_path = _string(raw["path"], f"{description}.path")
    require(Path(collector_path).is_absolute(), f"{description}.path is not absolute")
    digest = _string(raw["sha256"], f"{description}.sha256")
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"{description}.sha256 is invalid")
    _nonnegative_integer(raw["size"], f"{description}.size")
    _nonnegative_integer(raw["mode"], f"{description}.mode")
    actual = _external_identity(path, description + " supplied path")
    require(
        actual["sha256"] == digest and actual["size"] == raw["size"] and actual["mode"] == raw["mode"],
        f"{description} supplied bytes differ",
    )
    return {"mode": raw["mode"], "path": collector_path, "sha256": digest, "size": raw["size"]}


def _write_new_bytes(path: Path, data: bytes) -> None:
    require(not path.exists() and not path.is_symlink(), f"evidence artifact already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    _physical_path(path.parent, "evidence artifact parent", directory=True)
    try:
        with path.open("xb") as stream:
            stream.write(data)
    except OSError as error:
        raise NativeDeclarationAbiError(f"cannot write evidence artifact {path}: {error}") from error


def _write_new_text(path: Path, text: str) -> None:
    require(type(text) is str, "evidence text is invalid")
    _write_new_bytes(path, text.encode("utf-8"))


def _write_new_json(path: Path, value: object) -> None:
    _write_new_text(path, json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")


def _snapshot_source_files(output: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for relative in SOURCE_FILES:
        source = ROOT / relative
        original = _source_identity(source, f"declaration ABI source {relative}")
        destination = output / "inputs" / "source" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(source, destination, follow_symlinks=False)
        except OSError as error:
            raise NativeDeclarationAbiError(f"cannot retain declaration ABI source {relative}: {error}") from error
        retained = _artifact_identity(output, destination, f"retained declaration ABI source {relative}")
        require(
            original["sha256"] == retained["sha256"]
            and original["size"] == retained["size"]
            and original["mode"] == retained["mode"],
            f"retained declaration ABI source differs: {relative}",
        )
        records.append({"original": original, "retained": retained})
    return records


def _validate_source_snapshots(output: Path, value: object) -> list[dict[str, Any]]:
    require(isinstance(value, list) and len(value) == len(SOURCE_FILES), "declaration ABI source snapshot roster differs")
    records: list[dict[str, Any]] = []
    for relative, raw in zip(SOURCE_FILES, value, strict=True):
        item = _exact_keys(raw, {"original", "retained"}, f"declaration ABI source snapshot {relative}")
        original = _source_identity(ROOT / relative, f"current declaration ABI source {relative}")
        require(strict_equal(item["original"], original), f"current declaration ABI source changed: {relative}")
        retained = _artifact_identity(output, output / "inputs" / "source" / relative, f"retained declaration ABI source {relative}")
        require(strict_equal(item["retained"], retained), f"retained declaration ABI source changed: {relative}")
        require(
            original["sha256"] == retained["sha256"]
            and original["size"] == retained["size"]
            and original["mode"] == retained["mode"],
            f"declaration ABI source snapshot pair differs: {relative}",
        )
        records.append({"original": original, "retained": retained})
    return records


def _matrix_projection() -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate the checked callable matrix before projecting its routes.

    The projection is deliberately the same narrow hand-off used by the
    selection reader.  The matrix collector remains the one owner of raw AST
    and profile collection.
    """
    try:
        contract = header_abi_matrix.load_contract()
        report_path = contract.generated_report
        report = read_json_object(report_path, "checked header ABI matrix report")
        header_abi_matrix.validate_checked_report(report, contract)
        provenance = {
            "report": _source_identity(report_path, "checked header ABI matrix report"),
            "reader": _source_identity(Path(header_abi_matrix.__file__), "header ABI matrix reader"),
            "contract": _source_identity(header_abi_matrix.CONTRACT_PATH, "header ABI matrix contract"),
            "extension_contract": _source_identity(
                header_abi_matrix.callable_extension_contract.CONTRACT_PATH,
                "header callable extension contract",
            ),
        }
        projection = callable_declarations.matrix_projection_from_checked_report(
            report,
            provenance=provenance,
        )
    except (ValueError, OSError) as error:
        raise NativeDeclarationAbiError(f"checked callable matrix rejected: {error}") from error
    return projection, provenance


def _callable_partition() -> tuple[list[str], dict[str, Any], list[dict[str, str]], dict[str, Any]]:
    """Reconstruct the existing selected callable partition from its owner.

    This component never carries a second 1,511-name policy.  It asks the
    existing disposition reader to reconstruct its checked report, then passes
    exactly that partition to the callable declaration account.
    """
    try:
        contract = callable_disposition.load_contract()
        checked = read_json_object(contract.generated_report, "checked callable disposition report")
        callable_disposition.validate_checked_report(checked, contract)
        rebuilt = callable_disposition.build_report(contract)
        require(strict_equal(checked, rebuilt), "checked callable disposition reconstruction differs")
        feature_rows = feature_archive_roster.load_feature_archive_roster()
    except (ValueError, OSError) as error:
        raise NativeDeclarationAbiError(f"selected callable partition rejected: {error}") from error
    primary = checked.get("primary_disposition")
    require(isinstance(primary, Mapping), "selected callable primary disposition is invalid")
    providers: set[str] = set()
    default_static = primary.get("default_static")
    require(isinstance(default_static, Mapping) and isinstance(default_static.get("members"), list),
            "selected callable default-static partition is invalid")
    providers.update(_symbol(name, "selected default-static callable") for name in default_static["members"])
    for field in ("verified_feature_archives", "declared_unverified_feature_archives"):
        records = primary.get(field)
        require(isinstance(records, list), f"selected callable {field} partition is invalid")
        for index, raw in enumerate(records):
            require(isinstance(raw, Mapping) and isinstance(raw.get("members"), list),
                    f"selected callable {field} record {index} is invalid")
            providers.update(_symbol(name, f"selected callable {field} member") for name in raw["members"])
    deferred: dict[str, Any] = {}
    raw_deferred = primary.get("deferred_owner_groups")
    require(isinstance(raw_deferred, list), "selected callable deferred partition is invalid")
    for index, raw in enumerate(raw_deferred):
        require(isinstance(raw, Mapping) and isinstance(raw.get("members"), list),
                f"selected deferred callable group {index} is invalid")
        for name in raw["members"]:
            name = _symbol(name, "selected deferred callable")
            require(name not in deferred, f"selected deferred callable repeats: {name}")
            deferred[name] = copy.deepcopy(dict(raw))
    abi_only: list[dict[str, str]] = []
    for row in feature_rows:
        for name in row.abi_only_callables:
            abi_only.append({"name": name, "owner": row.identifier, "state": row.state, "runner": row.runner})
    abi_only.sort(key=lambda item: item["name"])
    require(len(abi_only) == len({item["name"] for item in abi_only}), "feature ABI-only callable names repeat")
    require(providers.isdisjoint(deferred), "selected callable provider/deferred partitions overlap")
    require(not (providers | set(deferred)) & {item["name"] for item in abi_only},
            "selected ABI-only callable overlaps the header partition")
    source = {
        "contract": _source_identity(callable_disposition.CONTRACT_PATH, "callable disposition contract"),
        "reader": _source_identity(Path(callable_disposition.__file__), "callable disposition reader"),
        "report": _source_identity(contract.generated_report, "callable disposition report"),
        "feature_roster_reader": _source_identity(Path(feature_archive_roster.__file__), "feature archive roster reader"),
        "inventory": _source_identity(contract.callable_inventory, "callable inventory"),
    }
    return sorted(providers), deferred, abi_only, source


def derive_callable_plan(header_report: Path) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    """Replay one header envelope and derive the ordinary-object plan.

    The public header reader is called exactly once here.  This avoids a second
    raw compiler replay while still refusing a malformed raw envelope before
    source generation begins.
    """
    header_report = _physical_path(header_report, "header declaration report", directory=False)
    try:
        envelope = declaration_inventory.validate_report(header_report, project_include=ROOT / "include")
    except (ValueError, OSError) as error:
        raise NativeDeclarationAbiError(f"header declaration report rejected: {error}") from error
    require(isinstance(envelope, Mapping) and set(envelope) == {"current_selecting_source", "report"},
            "header declaration replay envelope fields differ")
    current = envelope["current_selecting_source"]
    require(isinstance(current, Mapping), "header declaration replay source status is invalid")
    require(_boolean(current.get("matches_retained"), "header declaration replay source match"),
            "header declaration report is historical source drift, not a fresh object input")
    require(isinstance(current.get("differences"), list) and not current["differences"],
            "header declaration replay source differences are not empty")
    providers, deferred, abi_only, partition_source = _callable_partition()
    matrix_projection, matrix_provenance = _matrix_projection()
    try:
        account = callable_declarations.account_declarations(
            envelope,
            provider_names=providers,
            deferred=deferred,
            abi_only_callables=abi_only,
            matrix_projection=matrix_projection,
        )
    except (ValueError, OSError) as error:
        raise NativeDeclarationAbiError(f"selected callable declaration account rejected: {error}") from error
    require(account.get("selected_callable_declaration_status") == "proved-with-explicit-boundaries",
            "selected callable declaration account is not current")
    plans = linkage_jobs_from_callable_account(account)
    plan_source = {
        "account_schema": account.get("schema"),
        "account_status": account.get("selected_callable_declaration_status"),
        "current_selecting_source": copy.deepcopy(dict(current)),
        "matrix_provenance": matrix_provenance,
        "partition_source": partition_source,
        "provider_count": len(providers),
        "deferred_count": len(deferred),
        "abi_only_count": len(abi_only),
    }
    return account, plans, plan_source


def _require_native_collection_context() -> str:
    """Admit only the fixed pinned x86 container collection context."""
    require(ROOT == SOURCE_MOUNT, "native declaration ABI collection requires the fixed /workspace checkout mount")
    uname = os.uname()
    require(uname.sysname == "Linux" and uname.machine == "x86_64", "native declaration ABI collection requires Linux/x86_64")
    image = os.environ.get(IMAGE_ENV)
    require(type(image) is str and IMAGE_PATTERN.fullmatch(image) is not None,
            f"{IMAGE_ENV} must name the resolved crabc-core-evidence digest")
    return image


def _bounded_workers(value: object) -> int:
    require(type(value) is int and 1 <= value <= MAX_WORKERS, f"workers must be an integer from 1 through {MAX_WORKERS}")
    return value


def _timeout(value: object) -> float:
    require(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)) and float(value) > 0,
            "command timeout must be a finite positive number")
    return float(value)


def _clean_environment(tmpdir: Path) -> dict[str, str]:
    tmpdir = _physical_path(tmpdir, "compiler temporary directory", directory=True)
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(tmpdir),
        "TZ": "UTC",
    }


def _run_bound_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> tuple[int, bytes, bytes]:
    require(isinstance(argv, Sequence) and not isinstance(argv, (str, bytes)) and bool(argv), "command argv is invalid")
    rendered = [_string(item, "command argv item") for item in argv]
    cwd = _physical_path(cwd, "command working directory", directory=True)
    timeout_seconds = _timeout(timeout_seconds)
    try:
        process = subprocess.Popen(
            rendered,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise NativeDeclarationAbiError(f"cannot start retained command {rendered[0]}: {error}") from error
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
        raise NativeDeclarationAbiError(f"retained command timed out after {timeout_seconds:g} seconds: {rendered[0]}") from error
    return process.returncode, stdout, stderr


def _tool_identity(path: Path, description: str) -> dict[str, Any]:
    physical = _physical_path(path, description, directory=False)
    require(bool(physical.stat().st_mode & 0o111), f"{description} is not executable")
    return {
        "mode": stat.S_IMODE(physical.stat().st_mode),
        "path": str(physical),
        "sha256": sha256_file(physical),
        "size": physical.stat().st_size,
    }


def _resource_tree(path: Path) -> dict[str, Any]:
    root = _physical_path(path, "compiler resource include root", directory=True)
    records: list[dict[str, Any]] = []
    try:
        paths = sorted(root.rglob("*"), key=lambda item: item.as_posix())
    except OSError as error:
        raise NativeDeclarationAbiError("cannot enumerate compiler resource include root") from error
    for item in paths:
        details = item.lstat()
        relative = item.relative_to(root).as_posix()
        require(not stat.S_ISLNK(details.st_mode), f"compiler resource include root has symlink: {relative}")
        if stat.S_ISDIR(details.st_mode):
            records.append({"kind": "directory", "mode": stat.S_IMODE(details.st_mode), "path": relative})
        elif stat.S_ISREG(details.st_mode):
            records.append({
                "kind": "file",
                "mode": stat.S_IMODE(details.st_mode),
                "path": relative,
                "sha256": sha256_file(item),
                "size": details.st_size,
            })
        else:
            raise NativeDeclarationAbiError(f"compiler resource include root has unsupported node: {relative}")
    require(bool(records), "compiler resource include root is empty")
    return {"path": str(root), "records": records}


def _capture_command(
    output: Path,
    directory: Path,
    label: str,
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> dict[str, Any]:
    require(re.fullmatch(r"[a-z][a-z0-9-]*", label) is not None, "raw command label is invalid")
    directory = _physical_path(directory, "raw command directory", directory=True)
    command_path = directory / f"{label}.command.json"
    stdout_path = directory / f"{label}.stdout"
    stderr_path = directory / f"{label}.stderr"
    status_path = directory / f"{label}.status.json"
    _write_new_json(command_path, list(argv))
    returncode, stdout, stderr = _run_bound_command(
        argv,
        cwd=cwd,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )
    _write_new_bytes(stdout_path, stdout)
    _write_new_bytes(stderr_path, stderr)
    _write_new_json(status_path, {"returncode": returncode})
    return {
        "argv": list(argv),
        "command": _artifact_identity(output, command_path, f"{label} command"),
        "cwd": str(_physical_path(cwd, "raw command cwd", directory=True)),
        "environment": dict(sorted(environment.items())),
        "returncode": returncode,
        "status": _artifact_identity(output, status_path, f"{label} status"),
        "stderr": _artifact_identity(output, stderr_path, f"{label} stderr"),
        "stdout": _artifact_identity(output, stdout_path, f"{label} stdout"),
    }


def _validate_command_record(
    output: Path,
    value: object,
    *,
    expected_argv: Sequence[str],
    expected_cwd: str,
    expected_environment: Mapping[str, str],
    label: str,
) -> dict[str, Any]:
    raw = _exact_keys(
        value,
        {"argv", "command", "cwd", "environment", "returncode", "status", "stderr", "stdout"},
        f"retained {label} command",
    )
    require(raw["argv"] == list(expected_argv), f"retained {label} argv differs")
    require(raw["cwd"] == expected_cwd, f"retained {label} cwd differs")
    require(raw["environment"] == dict(sorted(expected_environment.items())), f"retained {label} environment differs")
    require(type(raw["returncode"]) is int, f"retained {label} return code is invalid")
    command = _validate_artifact_descriptor(output, raw["command"], f"retained {label} command")
    stdout = _validate_artifact_descriptor(output, raw["stdout"], f"retained {label} stdout")
    stderr = _validate_artifact_descriptor(output, raw["stderr"], f"retained {label} stderr")
    status = _validate_artifact_descriptor(output, raw["status"], f"retained {label} status")
    require(command["path"].endswith(f"/{label}.command.json"), f"retained {label} command path differs")
    require(stdout["path"].endswith(f"/{label}.stdout"), f"retained {label} stdout path differs")
    require(stderr["path"].endswith(f"/{label}.stderr"), f"retained {label} stderr path differs")
    require(status["path"].endswith(f"/{label}.status.json"), f"retained {label} status path differs")
    retained_argv = _read_json_value(output / command["path"], f"retained {label} argv", list)
    require(retained_argv == list(expected_argv), f"retained {label} argv artifact differs")
    retained_status = _read_json_value(output / status["path"], f"retained {label} status", dict)
    require(retained_status == {"returncode": raw["returncode"]}, f"retained {label} status artifact differs")
    return {
        "argv": list(expected_argv),
        "command": command,
        "cwd": expected_cwd,
        "environment": dict(sorted(expected_environment.items())),
        "returncode": raw["returncode"],
        "status": status,
        "stderr": stderr,
        "stdout": stdout,
    }


def _require_command_artifact_paths(record: Mapping[str, Any], directory: Path, label: str) -> None:
    """Bind a retained command's four raw artifacts to its exact job slot."""
    directory = Path(directory)
    require(not directory.is_absolute() and ".." not in directory.parts, "raw command directory is not relative")
    expected = {
        "command": (directory / f"{label}.command.json").as_posix(),
        "stdout": (directory / f"{label}.stdout").as_posix(),
        "stderr": (directory / f"{label}.stderr").as_posix(),
        "status": (directory / f"{label}.status.json").as_posix(),
    }
    for field, path in expected.items():
        value = record.get(field)
        require(isinstance(value, Mapping) and value.get("path") == path,
                f"retained {label} {field} raw path differs")


def _collection_tools(output: Path, timeout_seconds: float) -> tuple[dict[str, Any], Path]:
    """Capture fixed compiler/readelf identities and controlled version output."""
    try:
        compiler_observation, resource_include = declaration_inventory.command_identity("clang")
    except (ValueError, OSError) as error:
        raise NativeDeclarationAbiError(f"pinned clang identity rejected: {error}") from error
    compiler_path = _physical_path(Path(_string(compiler_observation.get("executable_path"), "clang executable path")),
                                   "clang executable", directory=False)
    resource_include = _physical_path(resource_include, "clang resource include", directory=True)
    readelf_text = shutil.which("readelf")
    require(readelf_text is not None, "readelf is not on PATH")
    readelf_path = _physical_path(Path(readelf_text).resolve(), "readelf executable", directory=False)
    tool_dir = output / "inputs" / "tools"
    tool_dir.mkdir(parents=True, exist_ok=False)
    _physical_path(tool_dir, "declaration ABI tool evidence directory", directory=True)
    environment = _clean_environment(tool_dir)
    compiler_version = _capture_command(
        output,
        tool_dir,
        "clang-version",
        [str(compiler_path), "--version"],
        cwd=ROOT,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )
    readelf_version = _capture_command(
        output,
        tool_dir,
        "readelf-version",
        [str(readelf_path), "--version"],
        cwd=ROOT,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )
    require(compiler_version["returncode"] == 0 and readelf_version["returncode"] == 0,
            "pinned inspection tool version query failed")
    tools = {
        "clang": {
            "identity": _tool_identity(compiler_path, "clang executable"),
            "requested": "clang",
            "resource_include": _resource_tree(resource_include),
            "version": compiler_version,
        },
        "readelf": {
            "identity": _tool_identity(readelf_path, "readelf executable"),
            "requested": "readelf",
            "version": readelf_version,
        },
    }
    return tools, resource_include


def _profile_records() -> dict[str, callable_inventory.Profile]:
    try:
        contract = callable_inventory.load_contract()
    except (ValueError, OSError) as error:
        raise NativeDeclarationAbiError(f"header callable profile contract rejected: {error}") from error
    records = {profile.identifier: profile for profile in contract.profiles}
    require(set(records) == set(PROFILE_LANGUAGES), "header callable profile roster differs")
    require({key: item.language for key, item in records.items()} == PROFILE_LANGUAGES,
            "header callable profile languages differ")
    return records


def _compile_argv(
    compiler: Path,
    profile: callable_inventory.Profile,
    header_root: Path,
    resource_include: Path,
    linux_uapi_include: Path,
    source: Path,
    object_path: Path,
) -> list[str]:
    command = [str(compiler), "-x", "c" if profile.language == "c" else "c++", f"-std={profile.standard}"]
    if profile.language == "cxx":
        command.append("-nostdinc++")
    command.extend([
        "-nostdinc",
        "-I", str(header_root),
        "-isystem", str(resource_include),
        "-isystem", str(linux_uapi_include),
    ])
    command.extend(f"-D{item}" for item in profile.defines)
    # Direct address references are retained at O0.  These flags do not create
    # a prototype, select a provider, or turn an inline definition into an
    # undefined import; the post-compile classifier records either outcome.
    command.extend([
        "-fno-builtin", "-fno-inline", "-fdata-sections", "-O0",
        "-c", str(source), "-o", str(object_path),
    ])
    return command


def _job_directory(output: Path, plan: Mapping[str, Any]) -> Path:
    tree = plan.get("tree")
    header = _safe_relative(plan.get("header"), "linkage job header")
    profile = _string(plan.get("profile"), "linkage job profile")
    require(tree in {"candidate", "reference"} and profile in PROFILE_LANGUAGES,
            "linkage job identity is invalid")
    directory = output / "raw" / tree / header / profile
    require(not directory.exists() and not directory.is_symlink(), "linkage raw job directory repeats")
    directory.mkdir(parents=True)
    return _physical_path(directory, "linkage raw job directory", directory=True)


def _decode_raw_text(path: Path, description: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise NativeDeclarationAbiError(f"cannot read {description}: {error}") from error


def _collect_one_object_job(
    output: Path,
    ordinal: int,
    plan: Mapping[str, Any],
    *,
    tools: Mapping[str, Any],
    profiles: Mapping[str, callable_inventory.Profile],
    resource_include: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Compile one already authenticated direct-header source and inspect it."""
    require(type(ordinal) is int and ordinal >= 0, "linkage job ordinal is invalid")
    directory = _job_directory(output, plan)
    tree = plan["tree"]
    profile_name = plan["profile"]
    profile = profiles.get(profile_name)
    require(profile is not None and profile.language == plan["language"], "linkage job profile/language differs")
    header_root = ROOT / "include" if tree == "candidate" else Path("/opt/musl-1.2.6/include")
    linux_uapi_include = Path("/opt/linux-5.10-uapi/include")
    _physical_path(header_root, f"{tree} header root", directory=True)
    _physical_path(linux_uapi_include, "pinned Linux UAPI include root", directory=True)
    source = directory / ("source.cpp" if profile.language == "cxx" else "source.c")
    object_path = directory / "ordinary.o"
    _write_new_text(source, generated_source(plan))
    source_record = _artifact_identity(output, source, "linkage source")
    temporary = directory / "tmp"
    temporary.mkdir()
    environment = _clean_environment(temporary)
    clang = tools.get("clang")
    readelf = tools.get("readelf")
    require(isinstance(clang, Mapping) and isinstance(readelf, Mapping), "retained tool roster differs")
    clang_identity = _exact_keys(clang.get("identity"), {"mode", "path", "sha256", "size"}, "clang identity")
    readelf_identity = _exact_keys(readelf.get("identity"), {"mode", "path", "sha256", "size"}, "readelf identity")
    compile = _capture_command(
        output,
        directory,
        "compile",
        _compile_argv(
            Path(_string(clang_identity["path"], "clang path")),
            profile,
            header_root,
            resource_include,
            linux_uapi_include,
            source,
            object_path,
        ),
        cwd=ROOT,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )
    require(compile["returncode"] == 0, f"ordinary declaration compile failed: {tree}:{plan['header']}:{profile_name}")
    object_record = _artifact_identity(output, object_path, "ordinary declaration object")
    symbols = _capture_command(
        output,
        directory,
        "symbols",
        [_string(readelf_identity["path"], "readelf path"), "-sW", str(object_path)],
        cwd=ROOT,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )
    relocations = _capture_command(
        output,
        directory,
        "relocations",
        [_string(readelf_identity["path"], "readelf path"), "-rW", str(object_path)],
        cwd=ROOT,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )
    require(symbols["returncode"] == 0 and relocations["returncode"] == 0,
            f"ordinary declaration readelf failed: {tree}:{plan['header']}:{profile_name}")
    symbol_rows = parse_symbol_table(_decode_raw_text(output / symbols["stdout"]["path"], "ordinary symbol output"))
    relocation_rows = parse_relocations(_decode_raw_text(output / relocations["stdout"]["path"], "ordinary relocation output"))
    observation = evaluate_object_linkage(plan, symbol_rows, relocation_rows)
    require(not temporary.exists() or temporary.is_dir(), "ordinary declaration compiler temporary path changed")
    shutil.rmtree(temporary)
    return {
        "header": plan["header"],
        "language": plan["language"],
        "names": list(plan["names"]),
        "object": object_record,
        "observations": observation,
        "ordinal": ordinal,
        "profile": profile_name,
        "raw": {
            "compile": compile,
            "relocations": relocations,
            "source": source_record,
            "symbols": symbols,
        },
        "references": copy.deepcopy(plan["references"]),
        "tree": tree,
    }


def _summary(jobs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    require(isinstance(jobs, Sequence) and not isinstance(jobs, (str, bytes)) and bool(jobs),
            "ordinary declaration job roster is empty")
    references: list[Mapping[str, Any]] = []
    observations: list[Mapping[str, Any]] = []
    for job in jobs:
        require(isinstance(job, Mapping), "ordinary declaration job is invalid")
        raw_references = job.get("references")
        raw_observations = job.get("observations")
        require(isinstance(raw_references, list) and isinstance(raw_observations, list),
                "ordinary declaration job observations are invalid")
        references.extend(item for item in raw_references if isinstance(item, Mapping))
        observations.extend(item for item in raw_observations if isinstance(item, Mapping))
    require(len(references) == len(observations), "ordinary declaration observation count differs")
    statuses = Counter(_string(item.get("status"), "ordinary declaration observation status") for item in observations)
    categories = Counter(_string(item.get("category"), "ordinary declaration observation category") for item in observations)
    return {
        "cxx_job_count": sum(job.get("language") == "cxx" for job in jobs),
        "job_count": len(jobs),
        "language_counts": dict(sorted(Counter(_string(job.get("language"), "ordinary declaration job language") for job in jobs).items())),
        "observation_count": len(observations),
        "observation_status_counts": dict(sorted(statuses.items())),
        "reference_category_counts": dict(sorted(categories.items())),
        "reference_count": len(references),
    }


def _report_status() -> dict[str, bool]:
    # Object spelling/import facts deliberately leave every selection, runtime,
    # family, and promotion gate open.
    return {
        "callable_declaration_abi_complete": False,
        "family_completion": False,
        "object_linkage_observed": True,
        "promotion_ready": False,
        "public_support": False,
        "record_layout_projection_observed": True,
        "runtime_semantics": False,
    }


def _collector_output_path(output: Path) -> str:
    output = _physical_path(output, "declaration ABI evidence directory", directory=True)
    require(output.is_relative_to(ROOT), "declaration ABI evidence directory escapes checkout")
    return str(SOURCE_MOUNT / output.relative_to(ROOT))


def _mapped_collector_output(output: Path, collector_path: object) -> Path:
    rendered = _string(collector_path, "retained declaration ABI collector output path")
    recorded = Path(rendered)
    require(recorded.is_absolute() and recorded.is_relative_to(SOURCE_MOUNT),
            "retained declaration ABI collector output path is outside /workspace")
    relative = recorded.relative_to(SOURCE_MOUNT)
    require(relative.parts[:3] == (".work", "x86_64", "native-declaration-abi"),
            "retained declaration ABI collector output path escapes its native work root")
    actual = _physical_path(output, "declaration ABI evidence directory", directory=True)
    require(actual.is_relative_to(ROOT) and actual.relative_to(ROOT) == relative,
            "host declaration ABI evidence path does not map to retained /workspace output")
    return recorded


def _admit_collector_header_report(path: Path) -> Path:
    report = _physical_path(path, "collector header declaration report", directory=False)
    require(report.is_relative_to(SOURCE_MOUNT / ".work" / "x86_64"),
            "collector header declaration report is outside the replayable /workspace/.work/x86_64 input root")
    return report


def _selection_source_seal() -> dict[str, Any]:
    try:
        seal = abi_inventory.collector_source_seal()
    except (ValueError, OSError) as error:
        raise NativeDeclarationAbiError(f"declaration ABI collector source is not clean: {error}") from error
    require(
        isinstance(seal, Mapping)
        and set(seal) == {"revision", "content_sha256", "clean"}
        and seal.get("clean") is True,
        "declaration ABI collector source seal differs",
    )
    return copy.deepcopy(dict(seal))


def _collection_execution(output: Path, image_id: str, source: Mapping[str, Any], workers: int, timeout_seconds: float) -> dict[str, Any]:
    return {
        "collector_output": _collector_output_path(output),
        "collector_source": copy.deepcopy(dict(source)),
        "image_id": image_id,
        "native_context": {"machine": "x86_64", "system": "Linux"},
        "source_mount": str(SOURCE_MOUNT),
        "timeout_seconds": timeout_seconds,
        "workers": workers,
    }


def _validate_execution(output: Path, value: object) -> tuple[Path, dict[str, Any]]:
    raw = _exact_keys(
        value,
        {"collector_output", "collector_source", "image_id", "native_context", "source_mount", "timeout_seconds", "workers"},
        "declaration ABI execution",
    )
    require(raw["source_mount"] == str(SOURCE_MOUNT), "declaration ABI source mount differs")
    require(type(raw["image_id"]) is str and IMAGE_PATTERN.fullmatch(raw["image_id"]) is not None,
            "declaration ABI image identity differs")
    require(raw["native_context"] == {"machine": "x86_64", "system": "Linux"},
            "declaration ABI native execution context differs")
    timeout_seconds = _timeout(raw["timeout_seconds"])
    workers = _bounded_workers(raw["workers"])
    source = _exact_keys(raw["collector_source"], {"revision", "content_sha256", "clean"}, "declaration ABI collector source")
    require(source["clean"] is True, "declaration ABI collector source was not clean")
    current = _selection_source_seal()
    require(strict_equal(source, current), "declaration ABI collector source changed")
    collector_output = _mapped_collector_output(output, raw["collector_output"])
    return collector_output, {
        "collector_output": str(collector_output),
        "collector_source": current,
        "image_id": raw["image_id"],
        "native_context": {"machine": "x86_64", "system": "Linux"},
        "source_mount": str(SOURCE_MOUNT),
        "timeout_seconds": timeout_seconds,
        "workers": workers,
    }


def _validate_tool_identity(value: object, description: str) -> dict[str, Any]:
    raw = _exact_keys(value, {"mode", "path", "sha256", "size"}, description)
    path = _string(raw["path"], f"{description}.path")
    require(Path(path).is_absolute() and Path(path).as_posix() == path, f"{description}.path is not absolute")
    digest = _string(raw["sha256"], f"{description}.sha256")
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"{description}.sha256 is invalid")
    mode = _nonnegative_integer(raw["mode"], f"{description}.mode")
    require(bool(mode & 0o111), f"{description}.mode is not executable")
    size = _positive_integer(raw["size"], f"{description}.size")
    return {"mode": mode, "path": path, "sha256": digest, "size": size}


def _validate_resource_tree(value: object) -> dict[str, Any]:
    raw = _exact_keys(value, {"path", "records"}, "retained compiler resource tree")
    path = _string(raw["path"], "retained compiler resource tree path")
    require(Path(path).is_absolute() and Path(path).as_posix() == path, "retained compiler resource tree path is invalid")
    records = raw["records"]
    require(isinstance(records, list) and bool(records), "retained compiler resource tree records are invalid")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(records):
        require(isinstance(item, Mapping), f"retained compiler resource tree record {index} is invalid")
        kind = item.get("kind")
        if kind == "directory":
            record = _exact_keys(item, {"kind", "mode", "path"}, f"retained compiler resource tree directory {index}")
        elif kind == "file":
            record = _exact_keys(item, {"kind", "mode", "path", "sha256", "size"}, f"retained compiler resource tree file {index}")
            digest = _string(record["sha256"], f"retained compiler resource tree file {index}.sha256")
            require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"retained compiler resource tree file {index}.sha256 is invalid")
            _nonnegative_integer(record["size"], f"retained compiler resource tree file {index}.size")
        else:
            raise NativeDeclarationAbiError(f"retained compiler resource tree record {index}.kind is invalid")
        relative = _safe_relative(record["path"], f"retained compiler resource tree record {index}.path")
        require(relative not in seen, f"retained compiler resource tree path repeats: {relative}")
        seen.add(relative)
        _nonnegative_integer(record["mode"], f"retained compiler resource tree record {index}.mode")
        normalized.append(copy.deepcopy(dict(record)))
    require([record["path"] for record in normalized] == sorted(record["path"] for record in normalized),
            "retained compiler resource tree records are not sorted")
    return {"path": path, "records": normalized}


def _validate_tools(output: Path, value: object, collector_output: Path, timeout_seconds: float) -> dict[str, Any]:
    raw = _exact_keys(value, {"clang", "readelf"}, "declaration ABI tool roster")
    normalized: dict[str, Any] = {}
    expected_environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(collector_output / "inputs" / "tools"),
        "TZ": "UTC",
    }
    for name in ("clang", "readelf"):
        item = raw[name]
        expected = {"identity", "requested", "version"}
        if name == "clang":
            expected.add("resource_include")
        record = _exact_keys(item, expected, f"retained {name} tool")
        require(record["requested"] == name, f"retained {name} tool requested spelling differs")
        identity = _validate_tool_identity(record["identity"], f"retained {name} tool identity")
        version = _validate_command_record(
            output,
            record["version"],
            expected_argv=[identity["path"], "--version"],
            expected_cwd=str(SOURCE_MOUNT),
            expected_environment=expected_environment,
            label=f"{name}-version",
        )
        _require_command_artifact_paths(version, Path("inputs") / "tools", f"{name}-version")
        require(version["returncode"] == 0, f"retained {name} version command failed")
        stdout = output / version["stdout"]["path"]
        require(bool(stdout.read_bytes()), f"retained {name} version output is empty")
        normalized[name] = {"identity": identity, "requested": name, "version": version}
        if name == "clang":
            normalized[name]["resource_include"] = _validate_resource_tree(record["resource_include"])
    return normalized


def _record_layout_projection() -> dict[str, Any]:
    path = ROOT / "compat" / "x86_64" / "generated" / "header_record_layout_matrix" / "report.json"
    return project_checked_record_layout(read_json_object(path, "checked record-layout report"))


def _validate_collector_header_identity(value: object, supplied: Path) -> dict[str, Any]:
    record = _validate_external_identity(value, supplied, "retained header declaration report")
    collector_path = Path(record["path"])
    require(collector_path.is_relative_to(SOURCE_MOUNT / ".work" / "x86_64"),
            "retained header declaration report collector path is outside the replayable fixed input root")
    return record


def _collect_jobs(
    output: Path,
    plans: Sequence[Mapping[str, Any]],
    *,
    tools: Mapping[str, Any],
    resource_include: Path,
    workers: int,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    profiles = _profile_records()
    results: dict[int, dict[str, Any]] = {}
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="declaration-abi-clang")
    futures: dict[concurrent.futures.Future[dict[str, Any]], int] = {}
    try:
        for ordinal, plan in enumerate(plans):
            futures[executor.submit(
                _collect_one_object_job,
                output,
                ordinal,
                plan,
                tools=tools,
                profiles=profiles,
                resource_include=resource_include,
                timeout_seconds=timeout_seconds,
            )] = ordinal
        for future in concurrent.futures.as_completed(futures):
            ordinal = futures[future]
            results[ordinal] = future.result()
    except BaseException:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        raise
    executor.shutdown(wait=True)
    require(sorted(results) == list(range(len(plans))), "ordinary declaration job completion roster differs")
    return [results[index] for index in range(len(plans))]


def build_report(
    *,
    output: Path,
    execution: Mapping[str, Any],
    header_report: Mapping[str, Any],
    source_snapshots: Sequence[Mapping[str, Any]],
    tools: Mapping[str, Any],
    callable_plan_source: Mapping[str, Any],
    plans: Sequence[Mapping[str, Any]],
    record_layout_projection: Mapping[str, Any],
    jobs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    require(len(plans) == len(jobs) and bool(plans), "ordinary declaration plan/job roster differs")
    for ordinal, (plan, job) in enumerate(zip(plans, jobs, strict=True)):
        require(isinstance(plan, Mapping) and isinstance(job, Mapping), "ordinary declaration plan/job is invalid")
        require(job.get("ordinal") == ordinal, "ordinary declaration job ordinal differs")
        for field in ("tree", "header", "profile", "language", "names", "references"):
            require(strict_equal(job.get(field), plan.get(field)), f"ordinary declaration job {ordinal}.{field} differs from its plan")
    summary = _summary(jobs)
    return {
        "callable_plan": copy.deepcopy(list(plans)),
        "callable_plan_source": copy.deepcopy(dict(callable_plan_source)),
        "execution": copy.deepcopy(dict(execution)),
        "header_declaration_report": copy.deepcopy(dict(header_report)),
        "inputs": {
            "source_snapshots": copy.deepcopy(list(source_snapshots)),
            "tools": copy.deepcopy(dict(tools)),
        },
        "jobs": copy.deepcopy(list(jobs)),
        "oracle": ORACLE,
        "record_layout_projection": copy.deepcopy(dict(record_layout_projection)),
        "schema": SCHEMA,
        "status": _report_status(),
        "summary": summary,
        "target": TARGET,
    }


def collect_report(
    *,
    output: Path,
    header_report: Path,
    workers: int = DEFAULT_WORKERS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Collect one fresh finite object/linkage report in the pinned image."""
    output = _physical_new_output(output)
    workers = _bounded_workers(workers)
    timeout_seconds = _timeout(timeout_seconds)
    image_id = _require_native_collection_context()
    header_report = _admit_collector_header_report(header_report)
    source_before = _selection_source_seal()
    try:
        output.mkdir()
        output = _physical_path(output, "declaration ABI evidence directory", directory=True)
        source_snapshots = _snapshot_source_files(output)
        header_identity = _external_identity(header_report, "header declaration report")
        _account, plans, callable_plan_source = derive_callable_plan(header_report)
        layout = _record_layout_projection()
        tools, resource_include = _collection_tools(output, timeout_seconds)
        jobs = _collect_jobs(
            output,
            plans,
            tools=tools,
            resource_include=resource_include,
            workers=workers,
            timeout_seconds=timeout_seconds,
        )
        source_after = _selection_source_seal()
        require(strict_equal(source_before, source_after), "declaration ABI collector source changed during collection")
        _validate_source_snapshots(output, source_snapshots)
        report = build_report(
            output=output,
            execution=_collection_execution(output, image_id, source_before, workers, timeout_seconds),
            header_report=header_identity,
            source_snapshots=source_snapshots,
            tools=tools,
            callable_plan_source=callable_plan_source,
            plans=plans,
            record_layout_projection=layout,
            jobs=jobs,
        )
        _write_new_json(output / "report.json", report)
        return report
    except BaseException:
        print(f"x86 native declaration ABI: retained collection at {output}", file=sys.stderr)
        raise


def _validate_job(
    output: Path,
    collector_output: Path,
    value: object,
    plan: Mapping[str, Any],
    ordinal: int,
    *,
    tools: Mapping[str, Any],
    profiles: Mapping[str, callable_inventory.Profile],
    resource_include: str,
) -> dict[str, Any]:
    raw = _exact_keys(
        value,
        {"header", "language", "names", "object", "observations", "ordinal", "profile", "raw", "references", "tree"},
        f"retained ordinary declaration job {ordinal}",
    )
    require(raw["ordinal"] == ordinal, f"retained ordinary declaration job {ordinal} ordinal differs")
    for field in ("tree", "header", "profile", "language", "names", "references"):
        require(strict_equal(raw[field], plan[field]), f"retained ordinary declaration job {ordinal}.{field} differs from current plan")
    tree = plan["tree"]
    header = plan["header"]
    profile_name = plan["profile"]
    profile = profiles.get(profile_name)
    require(profile is not None, f"retained ordinary declaration job {ordinal} has unknown profile")
    directory = collector_output / "raw" / tree / header / profile_name
    source_name = "source.cpp" if profile.language == "cxx" else "source.c"
    source_expected = directory / source_name
    object_expected = directory / "ordinary.o"
    raw_commands = _exact_keys(raw["raw"], {"compile", "relocations", "source", "symbols"}, f"retained ordinary declaration job {ordinal}.raw")
    source_record = _validate_artifact_descriptor(
        output,
        raw_commands["source"],
        f"retained ordinary declaration source {ordinal}",
    )
    require(source_record["path"] == (Path("raw") / tree / header / profile_name / source_name).as_posix(),
            f"retained ordinary declaration job {ordinal} source path differs")
    require(_decode_raw_text(output / source_record["path"], f"retained ordinary declaration source {ordinal}") == generated_source(plan),
            f"retained ordinary declaration job {ordinal} source bytes differ")
    object_actual = _validate_artifact_descriptor(output, raw["object"], f"retained ordinary declaration object {ordinal}")
    object_path = object_actual["path"]
    require(object_path == (Path("raw") / tree / header / profile_name / "ordinary.o").as_posix(),
            f"retained ordinary declaration object {ordinal} path differs")
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(directory / "tmp"),
        "TZ": "UTC",
    }
    candidate_root = SOURCE_MOUNT / "include" if tree == "candidate" else Path("/opt/musl-1.2.6/include")
    compile_argv = _compile_argv(
        Path(tools["clang"]["identity"]["path"]),
        profile,
        candidate_root,
        Path(resource_include),
        Path("/opt/linux-5.10-uapi/include"),
        source_expected,
        object_expected,
    )
    compile = _validate_command_record(
        output,
        raw_commands["compile"],
        expected_argv=compile_argv,
        expected_cwd=str(SOURCE_MOUNT),
        expected_environment=environment,
        label="compile",
    )
    _require_command_artifact_paths(compile, Path("raw") / tree / header / profile_name, "compile")
    symbols = _validate_command_record(
        output,
        raw_commands["symbols"],
        expected_argv=[tools["readelf"]["identity"]["path"], "-sW", str(object_expected)],
        expected_cwd=str(SOURCE_MOUNT),
        expected_environment=environment,
        label="symbols",
    )
    _require_command_artifact_paths(symbols, Path("raw") / tree / header / profile_name, "symbols")
    relocations = _validate_command_record(
        output,
        raw_commands["relocations"],
        expected_argv=[tools["readelf"]["identity"]["path"], "-rW", str(object_expected)],
        expected_cwd=str(SOURCE_MOUNT),
        expected_environment=environment,
        label="relocations",
    )
    _require_command_artifact_paths(relocations, Path("raw") / tree / header / profile_name, "relocations")
    require(compile["returncode"] == 0 and symbols["returncode"] == 0 and relocations["returncode"] == 0,
            f"retained ordinary declaration job {ordinal} command failed")
    symbol_rows = parse_symbol_table(_decode_raw_text(output / symbols["stdout"]["path"], f"retained ordinary symbol output {ordinal}"))
    relocation_rows = parse_relocations(_decode_raw_text(output / relocations["stdout"]["path"], f"retained ordinary relocation output {ordinal}"))
    observations = evaluate_object_linkage(plan, symbol_rows, relocation_rows)
    require(strict_equal(raw["observations"], observations), f"retained ordinary declaration job {ordinal} observation differs")
    return {
        "header": header,
        "language": profile.language,
        "names": list(plan["names"]),
        "object": object_actual,
        "observations": observations,
        "ordinal": ordinal,
        "profile": profile_name,
        "raw": {"compile": compile, "relocations": relocations, "source": source_record, "symbols": symbols},
        "references": copy.deepcopy(plan["references"]),
        "tree": tree,
    }


def validate_report(
    report_path: Path,
    *,
    header_report: Path,
) -> dict[str, Any]:
    """Replay a declaration ABI report without invoking a native tool.

    ``header_report`` is an explicit host mapping for the one retained public
    header envelope.  Its bytes must match the immutable collector input; the
    host reader never treats the collector's `/inputs/...` path as authority.
    """
    report_path = _physical_path(report_path, "native declaration ABI report", directory=False)
    require(report_path.name == "report.json", "native declaration ABI report name differs")
    output = _physical_path(report_path.parent, "native declaration ABI evidence directory", directory=True)
    require(output.parent == WORK_DIRECTORY, "native declaration ABI evidence directory differs")
    report = read_json_object(report_path, "native declaration ABI report")
    expected_keys = {
        "callable_plan", "callable_plan_source", "execution", "header_declaration_report", "inputs", "jobs",
        "oracle", "record_layout_projection", "schema", "status", "summary", "target",
    }
    require(set(report) == expected_keys, "native declaration ABI report fields differ")
    require(report["schema"] == SCHEMA and report["target"] == TARGET and report["oracle"] == ORACLE,
            "native declaration ABI report identity differs")
    collector_output, execution = _validate_execution(output, report["execution"])
    inputs = _exact_keys(report["inputs"], {"source_snapshots", "tools"}, "native declaration ABI inputs")
    source_snapshots = _validate_source_snapshots(output, inputs["source_snapshots"])
    tools = _validate_tools(output, inputs["tools"], collector_output, execution["timeout_seconds"])
    supplied_header_report = _physical_path(header_report, "supplied header declaration report", directory=False)
    header_identity = _validate_collector_header_identity(report["header_declaration_report"], supplied_header_report)
    _account, plans, callable_plan_source = derive_callable_plan(supplied_header_report)
    require(strict_equal(report["callable_plan"], plans), "retained callable object plan differs")
    require(strict_equal(report["callable_plan_source"], callable_plan_source), "retained callable plan source differs")
    layout = _record_layout_projection()
    require(strict_equal(report["record_layout_projection"], layout), "retained record-layout projection differs")
    raw_jobs = report["jobs"]
    require(isinstance(raw_jobs, list) and len(raw_jobs) == len(plans), "retained ordinary declaration job roster differs")
    profiles = _profile_records()
    resource_path = tools["clang"]["resource_include"]["path"]
    jobs = [
        _validate_job(
            output,
            collector_output,
            raw,
            plan,
            ordinal,
            tools=tools,
            profiles=profiles,
            resource_include=resource_path,
        )
        for ordinal, (raw, plan) in enumerate(zip(raw_jobs, plans, strict=True))
    ]
    summary = _summary(jobs)
    require(strict_equal(report["summary"], summary), "retained ordinary declaration summary differs")
    require(strict_equal(report["status"], _report_status()), "native declaration ABI status differs")
    return {
        "callable_plan": plans,
        "execution": execution,
        "header_declaration_report": header_identity,
        "record_layout_projection": layout,
        "report": report,
        "summary": summary,
    }


def validation_result(report_path: Path, replayed: Mapping[str, Any]) -> dict[str, Any]:
    """Render a compact host-side replay receipt without duplicating raw jobs."""
    report_path = _physical_path(report_path, "native declaration ABI report", directory=False)
    require(isinstance(replayed, Mapping) and set(replayed) == {
        "callable_plan", "execution", "header_declaration_report", "record_layout_projection", "report", "summary"
    }, "native declaration ABI replay result differs")
    return {
        "header_declaration_report": copy.deepcopy(dict(replayed["header_declaration_report"])),
        "report": _external_identity(report_path, "native declaration ABI report"),
        "schema": "crabc.x86_64-native-declaration-abi-validation/v1",
        "status": copy.deepcopy(dict(replayed["report"]["status"])),
        "summary": copy.deepcopy(dict(replayed["summary"])),
    }


def _parse_cli(arguments: Sequence[str] | None) -> argparse.Namespace:
    raw_arguments = list(sys.argv[1:] if arguments is None else arguments)
    for option in ("--header-report", "--output", "--workers", "--timeout-seconds"):
        appearances = sum(argument == option or argument.startswith(option + "=") for argument in raw_arguments)
        require(appearances <= 1, f"{option} is repeated")
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--collect", action="store_true", help="collect a fresh finite native declaration ABI report")
    modes.add_argument("--validate-report", type=Path, metavar="REPORT", help="host-replay one retained report")
    parser.add_argument("--header-report", required=True, type=Path, help="one retained public header declaration report")
    parser.add_argument("--output", type=Path, help="fresh output below .work/x86_64/native-declaration-abi")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help=f"bounded compiler workers (1 through {MAX_WORKERS})")
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="finite per-command timeout")
    parsed = parser.parse_args(raw_arguments)
    if parsed.collect:
        require(parsed.output is not None, "--collect requires --output")
    else:
        require(parsed.output is None, "--output is only valid with --collect")
        require(parsed.workers == DEFAULT_WORKERS and parsed.timeout_seconds == DEFAULT_TIMEOUT_SECONDS,
                "worker and timeout options are only valid with --collect")
    return parsed


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parse_cli(arguments)
    if parsed.collect:
        report = collect_report(
            output=parsed.output,
            header_report=parsed.header_report,
            workers=parsed.workers,
            timeout_seconds=parsed.timeout_seconds,
        )
        sys.stdout.write(json.dumps({"report": _artifact_identity(Path(parsed.output), Path(parsed.output) / "report.json", "native declaration ABI report")}, sort_keys=True) + "\n")
        return 0
    replayed = validate_report(parsed.validate_report, header_report=parsed.header_report)
    sys.stdout.write(json.dumps(validation_result(parsed.validate_report, replayed), sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except NativeDeclarationAbiError as error:
        print(f"ERROR: x86 native declaration ABI: {error}", file=sys.stderr)
        raise SystemExit(1)
