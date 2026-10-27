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
import struct
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
import native_abi_elf_facts as elf_facts
import native_callable_declarations as callable_declarations
import owned_posix_product_evidence as product_evidence


SCHEMA = "crabc.x86_64-native-declaration-abi/v2"
VALIDATION_SCHEMA = "crabc.x86_64-native-declaration-abi-validation/v2"
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
    r"^\s*(?P<offset>[0-9A-Fa-f]{16})\s+(?P<info>[0-9A-Fa-f]{16})\s+"
    r"(?P<type>R_X86_64_[A-Za-z0-9_]+)\s+[0-9A-Fa-f]{16}\s+"
    r"(?P<symbol>\S+)\s+(?P<sign>[+-])\s+(?P<addend>[0-9]+)\s*$"
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
    "finite_x86_64_pointer_relocation_witness": True,
    "c_and_cxx_object_emission": True,
    "header_replay_owned_elsewhere": True,
    "header_runtime_semantics": False,
    "mangled_name_is_not_linkage_proof": True,
    "record_layout_projection_only": True,
    "runtime_family_completion": False,
    "tool_inputs_authenticated": True,
}
REVIEWED_CPP_LINKAGE_BOUNDARY = {
    **callable_declarations.REVIEWED_CPP_LINKAGE_DIFFERENCE,
    "disposition": "oracle-declared-no-provider",
    "control_profiles": ["c11-gnu", "c11-strict", "cxx17-gnu", "cxx17-strict"],
    "candidate_linkages": ["static", "static-pie", "pie", "non-pie"],
    "reference_linkages": ["static", "shared"],
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
        "reviewed_cpp_linkage_boundary",
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
    require(strict_equal(raw["reviewed_cpp_linkage_boundary"], REVIEWED_CPP_LINKAGE_BOUNDARY),
            "reviewed C++ linkage boundary differs")
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
        "reviewed_cpp_linkage_boundary": copy.deepcopy(REVIEWED_CPP_LINKAGE_BOUNDARY),
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


def generated_source(plan: Mapping[str, Any], *, executable_probe: bool = False) -> str:
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
    if executable_probe:
        require(names == [REVIEWED_CPP_LINKAGE_BOUNDARY["name"]], "executable declaration probe scope differs")
        rendered.extend(["int main(void) { return crabc_native_declaration_abi_reference_0 == 0; }", ""])
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


def parse_relocations(text: str) -> list[dict[str, Any]]:
    """Parse the finite x86-64 address-initializer relocation witness."""
    require(type(text) is str, "relocation output is not text")
    require(text.endswith("\n"), "relocation output is not newline terminated")
    if text == NO_RELOCATIONS + "\n":
        return []
    tables: list[tuple[str, int, list[dict[str, Any]]]] = []
    current_name: str | None = None
    current_count: int | None = None
    current_rows: list[dict[str, Any]] | None = None
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
        info = int(match.group("info"), 16)
        addend = int(match.group("addend"), 10)
        if match.group("sign") == "-":
            addend = -addend
        current_rows.append(
            {
                "addend": addend,
                "offset": int(match.group("offset"), 16),
                "section": current_name,
                "symbol": match.group("symbol"),
                "symbol_index": info >> 32,
                "type": match.group("type"),
            }
        )
    finish()
    require(bool(tables), "relocation output has no relocation table")
    result: list[dict[str, Any]] = []
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
            holder_rows = [
                row
                for row in symbols
                if isinstance(row, Mapping) and row.get("name") == holder
            ]
            require(len(holder_rows) == 1, f"ordinary object holder roster differs for {name}")
            holder_row = holder_rows[0]
            require(
                holder_row.get("binding") == "LOCAL"
                and holder_row.get("visibility") == "DEFAULT"
                and holder_row.get("type") == "OBJECT"
                and type(holder_row.get("section")) is str
                and re.fullmatch(r"[1-9][0-9]*", holder_row["section"]) is not None
                and holder_row.get("size") == 8,
                f"ordinary object holder metadata differs for {name}",
            )
            holder_value = holder_row.get("value")
            require(
                type(holder_value) is str and re.fullmatch(r"[0-9a-f]{16}", holder_value) is not None,
                f"ordinary object holder value differs for {name}",
            )
            table = f".rela.data.{holder}"
            referenced = [row for row in relocations if isinstance(row, Mapping) and row.get("section") == table]
            require(len(referenced) == 1, f"ordinary object has no unambiguous retained relocation for {name}")
            relocation = referenced[0]
            observed_name = _symbol(relocation.get("symbol"), f"ordinary relocation symbol: {name}")
            require(relocation.get("type") == "R_X86_64_64", f"ordinary pointer relocation type differs for {name}")
            require(relocation.get("addend") == 0, f"ordinary pointer relocation addend differs for {name}")
            require(
                relocation.get("offset") == int(holder_value, 16),
                f"ordinary pointer relocation offset differs for {name}",
            )
            observed_rows = [
                row
                for row in symbols
                if isinstance(row, Mapping) and row.get("name") == observed_name and row.get("section") == "UND"
            ]
            require(len(observed_rows) == 1, f"ordinary object undefined symbol roster differs for {name}")
            row = observed_rows[0]
            require(row.get("binding") == "GLOBAL" and row.get("visibility") == "DEFAULT",
                    f"ordinary undefined reference metadata differs for {name}")
            require(
                relocation.get("symbol_index") == row.get("index"),
                f"ordinary pointer relocation symbol index differs for {name}",
            )
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
    "compat/x86_64/run_musl_oracle.sh",
    "compat/x86_64/musl_oracle.py",
    "compat/upstreams.toml",
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
    "compat/x86_64/native_abi_elf_facts.py",
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


def _header_snapshot_bytes(value: object, description: str) -> dict[str, Any]:
    """Project one already replayed header-envelope file snapshot exactly."""
    raw = _exact_keys(value, {"after", "before", "retained"}, description)
    records: dict[str, dict[str, Any]] = {}
    for label in ("before", "after", "retained"):
        record = _exact_keys(raw[label], {"path", "sha256", "size"}, f"{description}.{label}")
        path = _string(record["path"], f"{description}.{label}.path")
        digest = _string(record["sha256"], f"{description}.{label}.sha256")
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"{description}.{label}.sha256 is invalid")
        records[label] = {"path": path, "sha256": digest, "size": _nonnegative_integer(record["size"], f"{description}.{label}.size")}
    require(
        records["before"]["path"] == records["after"]["path"]
        and records["before"]["sha256"] == records["after"]["sha256"]
        and records["before"]["size"] == records["after"]["size"]
        and records["before"]["sha256"] == records["retained"]["sha256"]
        and records["before"]["size"] == records["retained"]["size"],
        f"{description} bytes differ",
    )
    return records["before"]


def _header_tool_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Project the one replayed public-header compiler envelope for this reader.

    The header reader authenticates its retained clang binary and any resource
    headers it observed.  This finite projection lets the ordinary-object
    reader bind to those exact bytes without replaying the public header report
    a second time.
    """
    report = envelope.get("report")
    require(isinstance(report, Mapping), "header declaration replay report is invalid")
    inputs = report.get("inputs")
    require(isinstance(inputs, Mapping), "header declaration replay inputs are invalid")
    compiler = inputs.get("compiler")
    require(isinstance(compiler, Mapping), "header declaration replay compiler input is invalid")
    require(
        set(compiler) == {"executable", "executable_original_path", "requested", "resource_include_original_path", "resource_query", "version"},
        "header declaration replay compiler input fields differ",
    )
    clang = _header_snapshot_bytes(compiler["executable"], "header declaration replay clang executable")
    clang_path = _string(compiler["executable_original_path"], "header declaration replay clang path")
    require(clang["path"] == clang_path and Path(clang_path).is_absolute(), "header declaration replay clang path differs")
    resource_include = _string(compiler["resource_include_original_path"], "header declaration replay resource include")
    resource_root = Path(resource_include)
    require(resource_root.is_absolute() and resource_root.as_posix() == resource_include, "header declaration replay resource include is invalid")
    dependencies = inputs.get("dependency_snapshots")
    require(isinstance(dependencies, list), "header declaration replay dependency snapshots are invalid")
    resource_headers: list[dict[str, Any]] = []
    for ordinal, item in enumerate(dependencies):
        require(isinstance(item, Mapping), f"header declaration replay dependency {ordinal} is invalid")
        if item.get("classification") != "compiler-resource":
            continue
        require(
            set(item) == {"classification", "key", "logical_path", "original_path_observation", "snapshot"},
            f"header declaration replay compiler resource dependency {ordinal} fields differ",
        )
        original = _string(item["original_path_observation"], f"header declaration replay compiler resource dependency {ordinal} path")
        original_path = Path(original)
        require(original_path.is_absolute() and original_path.is_relative_to(resource_root),
                f"header declaration replay compiler resource dependency {ordinal} escapes resource include")
        relative = original_path.relative_to(resource_root).as_posix()
        require(relative == _safe_relative(item["logical_path"], f"header declaration replay compiler resource dependency {ordinal} logical path"),
                f"header declaration replay compiler resource dependency {ordinal} logical path differs")
        snapshot = _header_snapshot_bytes(item["snapshot"], f"header declaration replay compiler resource dependency {ordinal} snapshot")
        require(snapshot["path"] == original, f"header declaration replay compiler resource dependency {ordinal} snapshot path differs")
        resource_headers.append({"path": relative, "sha256": snapshot["sha256"], "size": snapshot["size"]})
    require(resource_headers == sorted(resource_headers, key=lambda item: item["path"]),
            "header declaration replay compiler resource dependencies are not sorted")
    require(len({item["path"] for item in resource_headers}) == len(resource_headers),
            "header declaration replay compiler resource dependencies repeat")
    return {
        "clang": {"path": clang_path, "sha256": clang["sha256"], "size": clang["size"]},
        "resource_headers": resource_headers,
        "resource_include": resource_include,
    }


def _header_replay_envelope(
    header_report: Path,
    header_envelope: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    """Use one caller-authenticated header envelope or replay it locally.

    ``header_envelope`` is only for a composition that has just obtained the
    exact return value from ``header_declaration_inventory.validate_report``.
    It avoids rereading the complete retained raw header evidence.  The caller
    still supplies the physical report path: report validation binds that path
    to the declaration-ABI collector's retained input identity.
    """
    header_report = _physical_path(header_report, "header declaration report", directory=False)
    if header_envelope is None:
        try:
            envelope = declaration_inventory.validate_report(header_report, project_include=ROOT / "include")
        except (ValueError, OSError) as error:
            raise NativeDeclarationAbiError(f"header declaration report rejected: {error}") from error
    else:
        envelope = header_envelope
    require(isinstance(envelope, Mapping) and set(envelope) == {"current_selecting_source", "report"},
            "header declaration replay envelope fields differ")
    current = envelope["current_selecting_source"]
    require(isinstance(current, Mapping) and set(current) == {"matches_retained", "differences"},
            "header declaration replay source status is invalid")
    matches = _boolean(current["matches_retained"], "header declaration replay source match")
    require(isinstance(current["differences"], list), "header declaration replay source differences are invalid")
    require(matches is (not bool(current["differences"])), "header declaration replay source status differs")
    require(matches,
            "header declaration report is historical source drift, not a fresh object input")
    return envelope


def derive_callable_plan(
    header_report: Path,
    *,
    header_envelope: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Derive the finite plan from one replayed public-header envelope.

    With no ``header_envelope``, this remains the standalone reader path and
    replays the physical report.  Selection composition passes the envelope it
    already authenticated, so the same full header report feeds data,
    callable, and ordinary-object declaration evidence exactly once.
    """
    envelope = _header_replay_envelope(header_report, header_envelope)
    current = envelope["current_selecting_source"]
    tool_envelope = _header_tool_envelope(envelope)
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
    return account, plans, plan_source, tool_envelope


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


def _retain_tool_identity(output: Path, path: Path, destination: Path, description: str) -> dict[str, Any]:
    """Retain the inspection tool bytes absent from the public header envelope."""
    identity = _tool_identity(path, description)
    require(not destination.exists() and not destination.is_symlink(), f"{description} retained path already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _physical_path(destination.parent, f"{description} retained parent", directory=True)
    try:
        shutil.copy2(path, destination, follow_symlinks=False)
    except OSError as error:
        raise NativeDeclarationAbiError(f"cannot retain {description}: {error}") from error
    retained = _artifact_identity(output, destination, f"retained {description}")
    require(
        identity["mode"] == retained["mode"]
        and identity["sha256"] == retained["sha256"]
        and identity["size"] == retained["size"],
        f"retained {description} differs",
    )
    return {**identity, "retained": retained}


def _require_header_clang_identity(identity: Mapping[str, Any], header_tools: Mapping[str, Any]) -> None:
    header_clang = header_tools.get("clang")
    require(isinstance(header_clang, Mapping), "header compiler envelope clang identity is invalid")
    require(
        identity.get("path") == header_clang.get("path")
        and identity.get("sha256") == header_clang.get("sha256")
        and identity.get("size") == header_clang.get("size"),
        "ordinary declaration clang differs from the replayed public-header compiler envelope",
    )


def _resource_tree(
    output: Path,
    path: Path,
    *,
    retained_root: Path,
    header_tools: Mapping[str, Any],
) -> dict[str, Any]:
    """Retain the actual compiler resource tree used by ordinary compilation.

    The header envelope supplies any resource-header observations it owns.  A
    current envelope may observe none, so this companion retains every file in
    the exact `-isystem` root rather than treating a declared digest as bytes.
    """
    root = _physical_path(path, "compiler resource include root", directory=True)
    expected_root = header_tools.get("resource_include")
    require(str(root) == expected_root, "compiler resource root differs from the replayed public-header envelope")
    raw_header_records = header_tools.get("resource_headers")
    require(isinstance(raw_header_records, list), "header compiler resource roster is invalid")
    header_records: dict[str, Mapping[str, Any]] = {}
    for ordinal, item in enumerate(raw_header_records):
        require(isinstance(item, Mapping), f"header compiler resource record {ordinal} is invalid")
        relative = _safe_relative(item.get("path"), f"header compiler resource record {ordinal}.path")
        digest = _string(item.get("sha256"), f"header compiler resource record {ordinal}.sha256")
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"header compiler resource record {ordinal}.sha256 is invalid")
        size = _nonnegative_integer(item.get("size"), f"header compiler resource record {ordinal}.size")
        require(relative not in header_records, f"header compiler resource record repeats: {relative}")
        header_records[relative] = {"sha256": digest, "size": size}
    require(not retained_root.exists() and not retained_root.is_symlink(), "compiler resource retained root already exists")
    retained_root.mkdir(parents=True)
    _physical_path(retained_root, "retained compiler resource root", directory=True)
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
            destination = retained_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            _physical_path(destination.parent, "retained compiler resource parent", directory=True)
            try:
                shutil.copy2(item, destination, follow_symlinks=False)
            except OSError as error:
                raise NativeDeclarationAbiError(f"cannot retain compiler resource file {relative}: {error}") from error
            retained = _artifact_identity(output, destination, f"retained compiler resource file {relative}")
            require(
                retained["mode"] == stat.S_IMODE(details.st_mode)
                and retained["sha256"] == sha256_file(item)
                and retained["size"] == details.st_size,
                f"retained compiler resource file differs: {relative}",
            )
            record = {
                "kind": "file",
                "mode": stat.S_IMODE(details.st_mode),
                "path": relative,
                "retained": retained,
                "sha256": retained["sha256"],
                "size": retained["size"],
            }
            expected = header_records.get(relative)
            if expected is not None:
                require(
                    record["sha256"] == expected["sha256"] and record["size"] == expected["size"],
                    f"compiler resource file differs from the replayed public-header envelope: {relative}",
                )
            records.append(record)
        else:
            raise NativeDeclarationAbiError(f"compiler resource include root has unsupported node: {relative}")
    observed_files = {record["path"] for record in records if record["kind"] == "file"}
    require(set(header_records).issubset(observed_files), "header compiler resource file is absent from ordinary compiler resource root")
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
    returncode, stdout, stderr = _run_bound_command(argv, cwd=cwd, environment=environment, timeout_seconds=timeout_seconds)
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
    raw = _exact_keys(value, {"argv", "command", "cwd", "environment", "returncode", "status", "stderr", "stdout"},
                      f"retained {label} command")
    require(raw["argv"] == list(expected_argv), f"retained {label} command argv differs")
    require(raw["cwd"] == expected_cwd, f"retained {label} command cwd differs")
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
    status_value = read_json_object(output / status["path"], f"retained {label} status")
    require(status_value == {"returncode": raw["returncode"]}, f"retained {label} status value differs")
    command_value = _read_json_value(output / command["path"], f"retained {label} command", list)
    require(command_value == list(expected_argv), f"retained {label} command bytes differ")
    return {
        "argv": list(expected_argv), "command": command, "cwd": expected_cwd,
        "environment": dict(sorted(expected_environment.items())), "returncode": raw["returncode"],
        "status": status, "stderr": stderr, "stdout": stdout,
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


def _collection_tools(
    output: Path,
    timeout_seconds: float,
    *,
    header_tools: Mapping[str, Any],
) -> tuple[dict[str, Any], Path]:
    """Capture tools after joining the public-header compiler envelope."""
    try:
        compiler_observation, resource_include = declaration_inventory.command_identity("clang")
    except (ValueError, OSError) as error:
        raise NativeDeclarationAbiError(f"pinned clang identity rejected: {error}") from error
    compiler_path = _physical_path(Path(_string(compiler_observation.get("executable_path"), "clang executable path")),
                                   "clang executable", directory=False)
    resource_include = _physical_path(resource_include, "clang resource include", directory=True)
    clang_identity = _tool_identity(compiler_path, "clang executable")
    _require_header_clang_identity(clang_identity, header_tools)
    readelf_text = shutil.which("readelf")
    require(readelf_text is not None, "readelf is not on PATH")
    readelf_path = _physical_path(Path(readelf_text).resolve(), "readelf executable", directory=False)
    tool_dir = output / "inputs" / "tools"
    tool_dir.mkdir(parents=True, exist_ok=False)
    _physical_path(tool_dir, "declaration ABI tool evidence directory", directory=True)
    environment = _clean_environment(tool_dir)
    compiler_version = _capture_command(
        output, tool_dir, "clang-version", [str(compiler_path), "--version"], cwd=ROOT,
        environment=environment, timeout_seconds=timeout_seconds,
    )
    readelf_version = _capture_command(
        output, tool_dir, "readelf-version", [str(readelf_path), "--version"], cwd=ROOT,
        environment=environment, timeout_seconds=timeout_seconds,
    )
    require(compiler_version["returncode"] == 0 and readelf_version["returncode"] == 0,
            "pinned inspection tool version query failed")
    tools = {
        "clang": {
            "identity": clang_identity,
            "requested": "clang",
            "resource_include": _resource_tree(
                output, resource_include, retained_root=tool_dir / "clang-resource", header_tools=header_tools,
            ),
            "version": compiler_version,
        },
        "readelf": {
            "identity": _retain_tool_identity(output, readelf_path, tool_dir / "readelf", "readelf executable"),
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
    *,
    executable_probe: bool = False,
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
    if executable_probe:
        command.extend(["-fPIC", "-fno-stack-protector"])
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
    executable_probe: bool = False,
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
    _write_new_text(source, generated_source(plan, executable_probe=executable_probe))
    source_record = _artifact_identity(output, source, "linkage source")
    temporary = directory / "tmp"
    temporary.mkdir()
    environment = _clean_environment(temporary)
    clang = tools.get("clang")
    readelf = tools.get("readelf")
    require(isinstance(clang, Mapping) and isinstance(readelf, Mapping), "retained tool roster differs")
    clang_identity = clang.get("identity")
    readelf_identity = readelf.get("identity")
    require(isinstance(clang_identity, Mapping) and isinstance(readelf_identity, Mapping), "retained tool identities differ")
    compile = _capture_command(
        output,
        directory,
        "compile",
        _compile_argv(
            Path(_string(clang_identity.get("path"), "clang path")),
            profile,
            header_root,
            resource_include,
            linux_uapi_include,
            source,
            object_path,
            executable_probe=executable_probe,
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
        [_string(readelf_identity.get("path"), "readelf path"), "-sW", str(object_path)],
        cwd=ROOT,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )
    relocations = _capture_command(
        output,
        directory,
        "relocations",
        [_string(readelf_identity.get("path"), "readelf path"), "-rW", str(object_path)],
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


def _cpp_boundary_plans(plans: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    reviewed = REVIEWED_CPP_LINKAGE_BOUNDARY
    selected = [copy.deepcopy(dict(plan)) for plan in plans
                if plan.get("header") == reviewed["header"] and plan.get("profile") in reviewed["control_profiles"]]
    expected = [(tree, profile) for tree in ("candidate", "reference") for profile in reviewed["control_profiles"]]
    require([(plan["tree"], plan["profile"]) for plan in selected] == expected,
            "reviewed C++ linkage control roster differs")
    for plan in selected:
        require(plan["names"] == [reviewed["name"]] and len(plan["references"]) == 1
                and plan["references"][0]["category"] == "reference-backed"
                and plan["references"][0]["expected_observation"] == "ordinary-undefined-reference",
                "reviewed C++ linkage declaration scope differs")
    return selected


def reviewed_cpp_linkage_boundary(
    plans: Sequence[Mapping[str, Any]], jobs: Sequence[Mapping[str, Any]],
    providers: Mapping[str, Sequence[Mapping[str, Any]]],
) -> dict[str, Any]:
    """Account the exact unusable oracle C++ declaration without remapping it.

    The C declaration and the candidate C bridge still require ordinary links.
    The mangled reference remains an observed mismatch; the bounded disposition
    requires its absence from both complete pinned provider inventories.
    """
    selected = _cpp_boundary_plans(plans)
    require(len(jobs) == len(selected), "reviewed C++ linkage object roster differs")
    reference_indices = []
    reviewed = REVIEWED_CPP_LINKAGE_BOUNDARY
    for index, (plan, job) in enumerate(zip(selected, jobs, strict=True)):
        require(all(strict_equal(job.get(key), plan[key]) for key in plan),
                "reviewed C++ linkage object does not join its declaration")
        observation = job.get("observations")
        require(isinstance(observation, list) and len(observation) == 1,
                "reviewed C++ linkage reference observation roster differs")
        if plan["tree"] == "reference" and plan["profile"] in reviewed["profiles"]:
            expected = {
                "category": "reference-backed", "expected_symbol": reviewed["name"],
                "holder": plan["references"][0]["holder"], "observed_symbol": reviewed["reference_symbol"],
                "relocation_type": "R_X86_64_64", "status": "ordinary-linkage-identity-mismatch",
            }
            reference_indices.append(index)
        else:
            expected = {"category": "reference-backed", "name": reviewed["name"],
                        "status": "ordinary-undefined-reference", "symbol": reviewed["candidate_symbol"]}
        require(strict_equal(observation, [expected]), "reviewed C++ linkage reference spelling differs")
    require(set(providers) == set(reviewed["reference_linkages"]), "reviewed oracle provider inventory roster differs")
    c_providers = {}
    for form, rows in providers.items():
        require(isinstance(rows, Sequence) and not isinstance(rows, (str, bytes)) and bool(rows),
                "reviewed oracle provider inventory is absent")
        require(not any(row.get("name") == reviewed["reference_symbol"] and row.get("section_index") != "UND"
                        for row in rows), "reviewed oracle C++ declaration unexpectedly has a provider")
        c_rows = [dict(row) for row in rows if row.get("name") == reviewed["candidate_symbol"]
                  and row.get("section_index") != "UND"]
        require(len(c_rows) == 1 and c_rows[0].get("binding") in {"GLOBAL", "WEAK"}
                and c_rows[0].get("visibility") == "DEFAULT" and c_rows[0].get("type") == "FUNC",
                "reviewed oracle C provider differs")
        c_providers[form] = c_rows[0]
    return {**copy.deepcopy(reviewed), "reference_job_indices": reference_indices, "c_providers": c_providers}


def _selected_callable_declaration_types() -> dict[str, Any]:
    contract = callable_inventory.load_contract()
    report = read_json_object(contract.generated_inventory, "checked header callable inventory")
    require(report.get("schema") == callable_inventory.SCHEMA,
            "checked header callable inventory schema differs")
    records = report.get("callables")
    require(isinstance(records, list), "checked header callable inventory rows are absent")

    def selected_type(tree: str, name: str, profile: str) -> str:
        rows = [row for row in records if isinstance(row, Mapping) and row.get("tree") == tree
                and row.get("name") == name and row.get("profile") == profile
                and row.get("classification") == "external" and row.get("declaration_kind") == "function"]
        require(len(rows) == 1
                and rows[0].get("declaring_header") == ("alloca.h" if name == "alloca" else "sys/soundcard.h")
                and type(rows[0].get("type")) is str and bool(rows[0]["type"]),
                f"checked {tree} {name} declaration type differs")
        return rows[0]["type"]

    return {
        "alloca": selected_type("candidate", "alloca", "c11-gnu"),
        "seqbuf_dump": {
            tree: {
                "c": selected_type(tree, "seqbuf_dump", "c11-gnu"),
                "cxx": selected_type(tree, "seqbuf_dump", "cxx17-gnu"),
            }
            for tree in ("candidate", "reference")
        },
    }


def _selected_deferred_owner_map(account: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    rows = account.get("deferred")
    require(isinstance(rows, list) and bool(rows), "selected deferred callable account is absent")
    members_by_id: dict[str, list[str]] = {}
    owners_by_id: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        require(isinstance(row, Mapping), f"selected deferred callable row {index} is invalid")
        name = _symbol(row.get("name"), f"selected deferred callable row {index} name")
        group_id = _string(row.get("id"), f"selected deferred callable row {index} owner")
        resolution = _string(row.get("resolution"), f"selected deferred callable row {index} resolution")
        group = {"id": group_id, "resolution": resolution}
        require(group_id not in owners_by_id or owners_by_id[group_id] == group,
                f"selected deferred owner {group_id} changes resolution")
        owners_by_id[group_id] = group
        members_by_id.setdefault(group_id, []).append(name)
    return {
        name: {**owners_by_id[group_id], "members": sorted(members_by_id[group_id])}
        for group_id, names in members_by_id.items()
        for name in names
    }


def _selected_callable_boundary_summary(
    deferred: Mapping[str, Any],
    products: Mapping[str, Any],
    compiler: Mapping[str, Any],
    alloca: Mapping[str, Any],
    seqbuf: Mapping[str, Any],
    providers: Mapping[str, Any],
    raw_provider_observations: Mapping[str, Any],
    *,
    retained: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    def owner(name: str, resolution: str, description: str) -> dict[str, Any]:
        raw = deferred.get(name)
        require(isinstance(raw, Mapping) and raw.get("resolution") == resolution,
                f"selected {description} {resolution} owner receipt is missing or differs")
        members = raw.get("members")
        require(isinstance(members, list) and members == [name],
                f"selected {description} owner member roster differs")
        group_id = _string(raw.get("id"), f"selected {description} owner id")
        return {"id": group_id, "members": list(members), "resolution": resolution}

    alloca_owner = owner("alloca", "compiler-builtin", "alloca")
    seqbuf_owner = owner("seqbuf_dump", "consumer-supplied", "seqbuf_dump")
    no_provider_groups = {
        _string(value.get("id"), "selected no-provider owner id"): value
        for value in deferred.values()
        if isinstance(value, Mapping) and value.get("resolution") == "oracle-declared-no-provider"
    }
    require(len(no_provider_groups) == 1, "selected oracle no-provider owner roster differs")
    no_provider_raw = next(iter(no_provider_groups.values()))
    no_provider_members = no_provider_raw.get("members")
    require(isinstance(no_provider_members, list) and len(no_provider_members) == 9,
            "selected oracle no-provider roster differs")
    no_provider_members = [_symbol(name, "selected oracle no-provider member") for name in no_provider_members]
    require(no_provider_members == sorted(set(no_provider_members)),
            "selected oracle no-provider roster differs")
    no_provider_owner = {
        "id": next(iter(no_provider_groups)),
        "members": list(no_provider_members),
        "resolution": "oracle-declared-no-provider",
    }
    for name in no_provider_members:
        value = deferred.get(name)
        require(isinstance(value, Mapping) and value.get("id") == no_provider_owner["id"]
                and value.get("resolution") == no_provider_owner["resolution"]
                and value.get("members") == no_provider_members,
                "selected oracle no-provider roster differs")

    require(set(products) == {"static", "dynamic"}, "selected callable boundary product roster differs")
    product_rows: dict[str, dict[str, Any]] = {}
    for kind in ("static", "dynamic"):
        row = _exact_keys(products[kind], {"root", "manifest", "installed_headers", "libc"},
                          f"selected callable boundary {kind} product")
        root = _string(row["root"], f"selected callable boundary {kind} product root")
        root_path = Path(root)
        require(root_path.is_absolute() and root_path.is_relative_to(SOURCE_MOUNT / ".work"),
                f"selected callable boundary {kind} product root escapes checkout work")
        manifest = _exact_keys(row["manifest"], {"mode", "path", "sha256", "size"},
                               f"selected callable boundary {kind} manifest")
        libc = _exact_keys(row["libc"], {"mode", "path", "sha256", "size"},
                           f"selected callable boundary {kind} libc")
        headers = _exact_keys(row["installed_headers"], {"path", "tree_sha256"},
                              f"selected callable boundary {kind} headers")
        require(manifest["path"] == root + "/share/crabc/manifest.json"
                and headers["path"] == root + "/usr/include"
                and libc["path"] == root + ("/usr/lib/libc.a" if kind == "static" else "/usr/lib/libc.so"),
                f"selected callable boundary {kind} product paths differ")
        for identity, description in ((manifest, "manifest"), (libc, "libc")):
            require(type(identity["mode"]) is int and identity["mode"] >= 0
                    and type(identity["size"]) is int and identity["size"] > 0
                    and re.fullmatch(r"[0-9a-f]{64}", _string(identity["sha256"], f"selected {kind} {description} digest")) is not None,
                    f"selected callable boundary {kind} {description} identity differs")
        require(re.fullmatch(r"[0-9a-f]{64}", _string(headers["tree_sha256"], f"selected {kind} header tree digest")) is not None,
                f"selected callable boundary {kind} header tree identity differs")
        product_rows[kind] = copy.deepcopy(dict(row))
    require(product_rows["static"]["installed_headers"]["tree_sha256"]
            == product_rows["dynamic"]["installed_headers"]["tree_sha256"],
            "selected callable boundary installed header trees differ")

    compiler_row = _exact_keys(compiler, {"mode", "path", "sha256", "size"},
                               "selected callable boundary compiler")
    require(Path(_string(compiler_row["path"], "selected callable boundary compiler path")).is_absolute()
            and type(compiler_row["mode"]) is int and compiler_row["mode"] > 0
            and type(compiler_row["size"]) is int and compiler_row["size"] > 0
            and re.fullmatch(r"[0-9a-f]{64}", _string(compiler_row["sha256"], "selected callable boundary compiler digest")) is not None,
            "selected callable boundary compiler identity differs")
    declaration_types = _selected_callable_declaration_types()

    alloca_row = _exact_keys(alloca, {"header", "profile", "compiler", "qual_type", "undefined_symbols",
                                     "relocation_symbols", "links", "raw"},
                             "selected alloca compiler boundary")
    require(alloca_row["header"] == "alloca.h" and alloca_row["profile"] == "c11-gnu"
            and alloca_row["qual_type"] == declaration_types["alloca"],
            "alloca declaration differs")
    require(strict_equal(alloca_row["compiler"], compiler_row), "alloca compiler differs")
    require(alloca_row["undefined_symbols"] == [] and alloca_row["relocation_symbols"] == [],
            "alloca object imports a callable or emits an external relocation")
    links = alloca_row["links"]
    require(isinstance(links, list) and [link.get("linkage") for link in links if isinstance(link, Mapping)]
            == ["static", "dynamic"], "alloca product link roster differs")
    for index, link in enumerate(links):
        link = _exact_keys(link, {"linkage", "returncode", "raw"}, f"alloca product link {index}")
        raw = _exact_keys(link["raw"], {"command", "output", "receipt"}, f"alloca product link raw {index}")
        require(link.get("returncode") == 0 and all(isinstance(item, Mapping) and bool(item) for item in raw.values()),
                "alloca product link receipt is missing")
    alloca_receipt = {
        "owner": alloca_owner,
        "name": "alloca",
        "declaration": {"header": "alloca.h", "profile": "c11-gnu", "qual_type": declaration_types["alloca"]},
        "compiler": copy.deepcopy(dict(compiler_row)),
        "no_libc_import": {"undefined_symbols": [], "relocation_symbols": []},
        "links": copy.deepcopy(links),
        "raw": copy.deepcopy(dict(_exact_keys(alloca_row["raw"], {"source", "object", "symbols", "relocations", "compile"},
                                               "alloca raw observations"))),
    }
    require(all(isinstance(item, Mapping) and bool(item) for item in alloca_receipt["raw"].values()),
            "alloca raw artifact observation is missing")

    seqbuf_row = _exact_keys(seqbuf, {"jobs"}, "selected seqbuf_dump consumer boundary")
    raw_jobs = seqbuf_row["jobs"]
    require(isinstance(raw_jobs, list) and len(raw_jobs) == 4,
            "seqbuf_dump consumer job roster differs")
    jobs: list[dict[str, Any]] = []
    expected_jobs = [(tree, language, profile, symbol)
                     for tree in ("candidate", "reference")
                     for language, profile, symbol in (
                         ("c", "c11-gnu", "seqbuf_dump"),
                         ("cxx", "cxx17-gnu", "_Z11seqbuf_dumpv"),
                     )]
    for index, (raw_job, expected) in enumerate(zip(raw_jobs, expected_jobs, strict=True)):
        tree, language, profile, symbol = expected
        qual_type = declaration_types["seqbuf_dump"][tree][language]
        job = _exact_keys(raw_job, {"tree", "header", "language", "profile", "qual_type", "definition_symbol",
                                    "consumer_undefined_symbol", "same_language_link", "opposite_language_link", "raw"},
                          f"seqbuf_dump consumer job {index}")
        require((job["tree"], job["header"], job["language"], job["profile"], job["qual_type"],
                 job["definition_symbol"], job["consumer_undefined_symbol"])
                == (tree, "sys/soundcard.h", language, profile, qual_type, symbol, symbol),
                "seqbuf_dump declaration or consumer linkage differs")
        same_language = _exact_keys(job["same_language_link"], {"returncode", "undefined_symbols", "raw"},
                                    f"seqbuf_dump same-language link {index}")
        opposite_language = _exact_keys(job["opposite_language_link"],
                                         {"returncode", "undefined_symbols", "raw"},
                                         f"seqbuf_dump opposite-language link {index}")
        same_raw = _exact_keys(same_language["raw"], {"command", "output", "symbols", "relocations"},
                               f"seqbuf_dump same-language raw link {index}")
        opposite_raw = _exact_keys(opposite_language["raw"],
                                   {"command", "output", "symbols", "relocations"},
                                   f"seqbuf_dump opposite-language raw link {index}")
        require(all(isinstance(item, Mapping) and bool(item) for item in (*same_raw.values(), *opposite_raw.values())),
                f"seqbuf_dump linked raw observation {index} is missing")
        require(same_language.get("returncode") == 0
                and same_language.get("undefined_symbols") == [],
                "seqbuf_dump same-language consumer link differs")
        require(opposite_language.get("returncode") == 0
                and opposite_language.get("undefined_symbols") == [symbol],
                "seqbuf_dump opposite-language consumer link differs")
        raw = _exact_keys(job["raw"], {"definition_source", "definition_object", "definition_compile",
                                        "definition_symbols", "definition_relocations", "consumer_source",
                                        "consumer_object", "consumer_compile", "consumer_symbols", "consumer_relocations"},
                          f"seqbuf_dump raw consumer observations {index}")
        require(all(isinstance(item, Mapping) and bool(item) for item in raw.values()),
                f"seqbuf_dump raw consumer observation {index} is missing")
        jobs.append(copy.deepcopy(dict(job)))
    seqbuf_receipt = {
        "owner": seqbuf_owner,
        "name": "seqbuf_dump",
        "header": "sys/soundcard.h",
        "compiler": copy.deepcopy(dict(compiler_row)),
        "jobs": jobs,
    }

    require(set(providers) == {"candidate", "reference"}, "selected oracle provider inventory tree roster differs")
    require(set(raw_provider_observations) == {"candidate", "reference"},
            "selected oracle provider raw tree roster differs")
    provider_absence: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for tree in ("candidate", "reference"):
        require(set(providers[tree]) == {"static", "shared"},
                f"selected {tree} provider inventory roster differs")
        require(set(raw_provider_observations[tree]) == {"static", "shared"},
                f"selected {tree} provider raw inventory roster differs")
        provider_absence[tree] = {}
        for form in ("static", "shared"):
            raw_rows = providers[tree][form]
            require(isinstance(raw_rows, Sequence) and not isinstance(raw_rows, (str, bytes)) and bool(raw_rows),
                    f"selected {tree} {form} provider inventory is missing")
            matches = []
            for row in raw_rows:
                require(isinstance(row, Mapping), f"selected {tree} {form} provider row is invalid")
                if row.get("name") in no_provider_members and row.get("binding") in {"GLOBAL", "WEAK"} \
                        and row.get("section_index") != "UND":
                    matches.append({key: row.get(key) for key in ("name", "binding", "visibility", "section_index", "type")})
            require(not matches, f"selected {tree} {form} libc provides declared no-provider name(s)")
            raw_inventory = raw_provider_observations[tree][form]
            expected_raw = {"members", "headers", "sections", "symbols"} if form == "static" else {"symbols"}
            require(isinstance(raw_inventory, Mapping) and set(raw_inventory) == expected_raw
                    and all(isinstance(item, Mapping) and bool(item) for item in raw_inventory.values()),
                    f"selected {tree} {form} raw provider inventory is missing")
            provider_absence[tree][form] = matches
    no_provider_receipt = {
        "owner": no_provider_owner,
        "members": list(no_provider_members),
        "provider_absence": provider_absence,
        "raw_provider_observations": copy.deepcopy({tree: dict(forms) for tree, forms in raw_provider_observations.items()}),
    }
    summary = {
        "products": product_rows,
        "alloca": alloca_receipt,
        "seqbuf_dump": seqbuf_receipt,
        "oracle_no_provider": no_provider_receipt,
    }
    if retained is not None:
        require(strict_equal(retained, summary), "retained selected callable boundary differs")
    return summary


def oracle_static_provider_rows(members: Sequence[str], header_text: str, section_text: str,
                                symbol_text: str, archive: str) -> list[dict[str, Any]]:
    """Keep every archive member, including physically symbol-free ELF objects."""
    facts = abi_inventory.parse_archive_elf_facts(header_text, section_text, symbol_text, members,
                                                 expected_archive=archive)
    return [row for member in facts for table in member["symbol_tables"] for row in table["rows"]]


def _selected_callable_product_seal(static_product: Path, dynamic_product: Path) -> dict[str, Any]:
    products = {}
    for kind, supplied in (("static", static_product), ("dynamic", dynamic_product)):
        root = _physical_path(supplied, f"selected callable {kind} product", directory=True)
        require(root.is_relative_to(ROOT / ".work"), f"selected callable {kind} product escapes checkout work")
        root_path = str(SOURCE_MOUNT / root.relative_to(ROOT))
        manifest = _external_identity(root / "share/crabc/manifest.json", f"selected callable {kind} product manifest")
        manifest["path"] = root_path + "/share/crabc/manifest.json"
        libc_relative = "usr/lib/libc.a" if kind == "static" else "usr/lib/libc.so"
        libc = _external_identity(root / libc_relative, f"selected callable {kind} libc")
        libc["path"] = root_path + "/" + libc_relative
        try:
            header_digest = elf_facts.installed_header_tree_digest(root / "usr/include")
        except (ValueError, OSError, abi_inventory.InventoryError) as error:
            raise NativeDeclarationAbiError(f"selected callable {kind} installed header tree rejected: {error}") from error
        products[kind] = {
            "root": root_path,
            "manifest": manifest,
            "installed_headers": {"path": root_path + "/usr/include", "tree_sha256": header_digest},
            "libc": libc,
        }
    require(products["static"]["installed_headers"]["tree_sha256"]
            == products["dynamic"]["installed_headers"]["tree_sha256"],
            "selected callable installed header trees differ")
    return products


def _installed_product_header_root(product: Path) -> Path:
    product = _physical_path(product, "installed product header root", directory=True)
    require(product.is_relative_to(ROOT / ".work"), "installed product header root escapes checkout work")
    return SOURCE_MOUNT / product.relative_to(ROOT) / "usr/include"


def _candidate_bridge_provider(rows: Sequence[Mapping[str, Any]], name: str, form: str) -> Mapping[str, Any]:
    providers = [row for row in rows if row["name"] == name and row["section_index"] != "UND"]
    require(len(providers) == 1 and providers[0]["type"] == "FUNC"
            and providers[0]["binding"] in {"GLOBAL", "WEAK"}
            and providers[0]["visibility"] == "DEFAULT" and providers[0]["size_bytes"] > 0,
            f"reviewed owned {form} C bridge provider differs")
    return providers[0]


def physical_reference_join(path: Path, symbol_text: str, section_text: str, *, static: bool) -> dict[str, Any]:
    """Join the probe holder to a provider address or its physical dynamic relocation."""
    tables = abi_inventory.parse_elf_symbol_tables(symbol_text)
    symtabs = [table for table in tables if table["name"] == ".symtab"]
    require(len(symtabs) == 1, "linked declaration probe symbol table differs")
    holders = [row for row in symtabs[0]["rows"] if row["name"] == "crabc_native_declaration_abi_reference_0"]
    require(len(holders) == 1 and holders[0]["type"] == "OBJECT" and holders[0]["binding"] == "LOCAL"
            and holders[0]["visibility"] == "DEFAULT" and holders[0]["size_bytes"] == 8,
            "linked declaration probe holder differs")
    holder = holders[0]
    sections = abi_inventory.parse_elf_sections(section_text)["sections"]
    selected = [row for row in sections if str(row["index"]) == holder["section_index"]]
    require(len(selected) == 1 and selected[0]["type"] == "PROGBITS", "linked probe holder section differs")
    data = _physical_path(path, "linked declaration probe", directory=False).read_bytes()
    require(data[:7] == b"\x7fELF\x02\x01\x01" and len(data) >= 64 and struct.unpack_from("<H", data, 18)[0] == 62,
            "linked declaration probe ELF differs")
    address = int(holder["value"], 16)
    section = selected[0]
    displacement = address - int(section["address"], 16)
    require(0 <= displacement <= int(section["size"], 16) - 8, "linked probe holder escapes its section")
    offset = int(section["offset"], 16) + displacement
    require(0 <= offset <= len(data) - 8, "linked probe holder escapes physical bytes")
    pointer = struct.unpack_from("<Q", data, offset)[0]
    relocations = []
    for row in sections:
        if row["type"] != "RELA":
            continue
        start, size = int(row["offset"], 16), int(row["size"], 16)
        require(int(row["entry_size"], 16) == 24 and size % 24 == 0 and 0 <= start <= len(data) - size,
                "linked probe relocation section differs")
        for position in range(start, start + size, 24):
            target, info, addend = struct.unpack_from("<QQq", data, position)
            if target == address:
                relocations.append({"type": info & 0xffffffff, "symbol_index": info >> 32,
                                    "addend": addend, "symbol_table": row["link"]})
    name = REVIEWED_CPP_LINKAGE_BOUNDARY["candidate_symbol"]
    if static:
        providers = [row for row in symtabs[0]["rows"] if row["name"] == name and row["section_index"] != "UND"]
        require(len(providers) == 1 and providers[0]["type"] == "FUNC" and providers[0]["size_bytes"] > 0
                and providers[0]["binding"] in {"LOCAL", "GLOBAL", "WEAK"}, "linked static C provider differs")
        provider = int(providers[0]["value"], 16)
        if relocations:
            require(relocations == [{"type": 8, "symbol_index": 0, "addend": provider,
                                     "symbol_table": relocations[0]["symbol_table"]}],
                    "linked static PIE pointer does not join its provider")
            require(pointer in {0, provider}, "linked static PIE pointer bytes differ")
        else:
            require(pointer == provider, "linked static pointer does not join its provider")
        return {"holder_address": address, "symbol": name, "provider_address": provider,
                "kind": "static-provider-address", "relocations": relocations}
    require(len(relocations) == 1 and relocations[0]["type"] == 1 and relocations[0]["addend"] == 0,
            "linked dynamic pointer relocation differs")
    relocation = relocations[0]
    dynsections = [row for row in sections if row["index"] == relocation["symbol_table"]]
    dynsym = [table for table in tables if table["name"] == ".dynsym"]
    require(len(dynsections) == len(dynsym) == 1 and dynsections[0]["type"] == "DYNSYM",
            "linked dynamic pointer symbol table differs")
    imported = [row for row in dynsym[0]["rows"] if row["row_index"] == relocation["symbol_index"]]
    require(len(imported) == 1 and imported[0]["name"] == name and imported[0]["section_index"] == "UND"
            and imported[0]["binding"] == "GLOBAL" and imported[0]["visibility"] == "DEFAULT",
            "linked dynamic pointer does not join its exact import")
    return {"holder_address": address, "symbol": name, "kind": "dynamic-provider-reference",
            "relocations": relocations}


def _selected_callable_boundary_evidence(
    boundary_output: Path,
    recorded_output: Path,
    *,
    static_product: Path,
    dynamic_product: Path,
    products: Mapping[str, Any],
    deferred: Mapping[str, Any],
    tools: Mapping[str, Any],
    extra_tools: Mapping[str, Any],
    resource_include: str,
    timeout_seconds: float,
    provider_rows: Mapping[str, Any],
    raw_provider_observations: Mapping[str, Any],
    command: Any,
    owned_linker: Mapping[str, Any],
    retained: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    replay = retained is not None
    if replay:
        retained = _exact_keys(retained, {"products", "alloca", "seqbuf_dump", "oracle_no_provider"},
                               "selected callable boundary receipt")
        retained_alloca = _exact_keys(
            retained["alloca"],
            {"owner", "name", "declaration", "compiler", "no_libc_import", "links", "raw"},
            "selected alloca boundary receipt",
        )
        retained_declaration = _exact_keys(
            retained_alloca["declaration"], {"header", "profile", "qual_type"},
            "selected alloca declaration receipt",
        )
        retained_no_import = _exact_keys(
            retained_alloca["no_libc_import"], {"undefined_symbols", "relocation_symbols"},
            "selected alloca import receipt",
        )
        previous_alloca = {
            "header": retained_declaration["header"],
            "profile": retained_declaration["profile"],
            "compiler": retained_alloca["compiler"],
            "qual_type": retained_declaration["qual_type"],
            "undefined_symbols": retained_no_import["undefined_symbols"],
            "relocation_symbols": retained_no_import["relocation_symbols"],
            "links": retained_alloca["links"],
            "raw": retained_alloca["raw"],
        }
        previous_seqbuf = _exact_keys(
            retained["seqbuf_dump"], {"owner", "name", "header", "compiler", "jobs"},
            "selected seqbuf_dump boundary receipt",
        )
        require(retained_alloca["name"] == "alloca" and previous_seqbuf["name"] == "seqbuf_dump",
                "selected callable boundary names differ")
    else:
        previous_alloca = None
        previous_seqbuf = None
    selected_root = boundary_output / "selected-callable-boundaries"
    if not replay:
        selected_root.mkdir()
    _physical_path(selected_root, "selected callable boundary evidence", directory=True)
    compiler = tools["clang"]["identity"]
    readelf = tools["readelf"]["identity"]["path"]
    linker = extra_tools["ld"]["identity"]["path"]
    profiles = _profile_records()
    def directory(path: Path) -> Path:
        if not replay:
            path.mkdir(parents=True)
        return _physical_path(path, "selected callable boundary raw directory", directory=True)

    def recorded(path: Path) -> Path:
        return recorded_output / path.relative_to(boundary_output)

    def source(path: Path, value: str, previous: object, description: str) -> dict[str, Any]:
        if replay:
            descriptor = _validate_artifact_descriptor(boundary_output, previous, description)
        else:
            _write_new_text(path, value)
            descriptor = _artifact_identity(boundary_output, path, description)
        require(descriptor["path"] == path.relative_to(boundary_output).as_posix()
                and _decode_raw_text(boundary_output / descriptor["path"], description) == value,
                f"{description} source bytes differ")
        return descriptor

    def object_file(path: Path, previous: object, description: str) -> dict[str, Any]:
        descriptor = (_validate_artifact_descriptor(boundary_output, previous, description) if replay
                      else _artifact_identity(boundary_output, path, description))
        require(descriptor["path"] == path.relative_to(boundary_output).as_posix(), f"{description} path differs")
        return descriptor

    def output_text(record: Mapping[str, Any], description: str) -> str:
        descriptor = _exact_keys(record.get("stdout"), {"mode", "path", "sha256", "size"},
                                 f"{description} stdout")
        return _decode_raw_text(boundary_output / descriptor["path"], description)

    def collect_object(
        *,
        tree: str,
        profile_name: str,
        role: str,
        source_text: str,
        previous: Mapping[str, Any] | None,
        header_root: Path,
    ) -> dict[str, Any]:
        profile = profiles.get(profile_name)
        require(profile is not None, f"selected {role} profile is not admitted")
        directory_path = directory(selected_root / role / tree / profile_name)
        source_path = directory_path / (role + ".cpp" if profile.language == "cxx" else role + ".c")
        object_path = directory_path / (role + ".o")
        previous = _exact_keys(previous, {"source", "object", "compile", "symbols", "relocations"},
                               f"selected {role} {tree}:{profile_name}") if replay else None
        source_record = source(
            source_path,
            source_text,
            previous["source"] if replay else None,
            f"selected {role} source",
        )
        source_recorded = recorded(source_path)
        object_recorded = recorded(object_path)
        expected_argv = _compile_argv(
            Path(compiler["path"]), profile, header_root, Path(resource_include),
            Path("/opt/linux-5.10-uapi/include"), source_recorded, object_recorded,
        )
        compile_record = command(
            directory_path,
            "compile",
            expected_argv,
            previous["compile"] if replay else None,
        )
        require(compile_record["returncode"] == 0,
                f"selected {role} header compile failed: {tree}:{profile_name}")
        object_record = object_file(object_path, previous["object"] if replay else None, f"selected {role} object")
        raw = {"source": source_record, "object": object_record, "compile": compile_record}
        for label, flags in (("symbols", ["-sW"]), ("relocations", ["-rW"])):
            inspection = command(
                directory_path,
                label,
                [readelf, *flags, str(object_recorded)],
                previous[label] if replay else None,
            )
            require(inspection["returncode"] == 0, f"selected {role} {label} inspection failed")
            raw[label] = inspection
        return {"path": object_path, "raw": raw,
                "symbols": parse_symbol_table(output_text(raw["symbols"], f"selected {role} symbol table")),
                "relocations": parse_relocations(output_text(raw["relocations"], f"selected {role} relocation table"))}

    alloca_previous = _exact_keys(
        previous_alloca,
        {"header", "profile", "compiler", "qual_type", "undefined_symbols", "relocation_symbols", "links", "raw"},
        "selected alloca receipt",
    ) if replay else None
    alloca_raw_previous = _exact_keys(alloca_previous["raw"], {"source", "object", "symbols", "relocations", "compile"},
                                      "selected alloca raw observations") if replay else None
    alloca_directory = directory(selected_root / "alloca" / "c11-gnu")
    alloca_source_path = alloca_directory / "source.c"
    alloca_object_path = alloca_directory / "alloca.o"
    alloca_source = (
        "#include <alloca.h>\n"
        "int main(void) {\n"
        "    volatile size_t size = 64;\n"
        "    volatile unsigned char *bytes = alloca(size);\n"
        "    bytes[0] = (unsigned char)size;\n"
        "    return bytes[0] != (unsigned char)size;\n"
        "}\n"
    )
    alloca_source_record = source(
        alloca_source_path,
        alloca_source,
        alloca_raw_previous["source"] if replay else None,
        "selected alloca source",
    )
    alloca_source_recorded = recorded(alloca_source_path)
    alloca_object_recorded = recorded(alloca_object_path)
    profile = profiles["c11-gnu"]
    alloca_argv = [
        str(compiler["path"]), "-x", "c", f"-std={profile.standard}", "-nostdinc",
        "-I", str(_installed_product_header_root(static_product)), "-isystem", resource_include,
        "-isystem", "/opt/linux-5.10-uapi/include", *[f"-D{value}" for value in profile.defines],
        "-O0", "-fno-stack-protector", "-fdata-sections", "-c",
        str(alloca_source_recorded), "-o", str(alloca_object_recorded),
    ]
    alloca_compile = command(alloca_directory, "compile", alloca_argv,
                             alloca_raw_previous["compile"] if replay else None)
    require(alloca_compile["returncode"] == 0, "selected alloca header compile failed")
    alloca_object_record = object_file(alloca_object_path,
                                       alloca_raw_previous["object"] if replay else None,
                                       "selected alloca object")
    alloca_raw: dict[str, Any] = {
        "source": alloca_source_record,
        "object": alloca_object_record,
        "compile": alloca_compile,
    }
    alloca_symbols = command(
        alloca_directory, "symbols", [readelf, "-sW", str(alloca_object_recorded)],
        alloca_raw_previous["symbols"] if replay else None,
    )
    alloca_relocations = command(
        alloca_directory, "relocations", [readelf, "-rW", str(alloca_object_recorded)],
        alloca_raw_previous["relocations"] if replay else None,
    )
    require(alloca_symbols["returncode"] == alloca_relocations["returncode"] == 0,
            "selected alloca ELF inspection failed")
    alloca_raw["symbols"] = alloca_symbols
    alloca_raw["relocations"] = alloca_relocations
    alloca_symbol_rows = parse_symbol_table(output_text(alloca_symbols, "selected alloca symbols"))
    alloca_relocation_rows = parse_relocations(output_text(alloca_relocations, "selected alloca relocations"))
    alloca_undefined = sorted({row["name"] for row in alloca_symbol_rows
                               if row["binding"] in {"GLOBAL", "WEAK"} and row["section"] == "UND" and row["name"]})
    alloca_external_relocations = sorted({row["symbol"] for row in alloca_relocation_rows
                                          if row["symbol"] in alloca_undefined})
    alloca_links = []
    previous_links = alloca_previous["links"] if replay else []
    require(isinstance(previous_links, list) if replay else True, "retained alloca product link roster is invalid")
    require(not replay or len(previous_links) == 2, "retained alloca product link roster differs")
    for index, (kind, product, form) in enumerate((("static", static_product, "static"),
                                                   ("dynamic", dynamic_product, "non-pie"))):
        previous_link = previous_links[index] if replay else None
        if replay:
            previous_link = _exact_keys(previous_link, {"linkage", "returncode", "raw"}, "retained alloca link")
            require(previous_link["linkage"] == kind, "retained alloca product link identity differs")
        link_directory = directory(selected_root / "alloca" / kind / "link")
        executable = link_directory / "probe"
        receipt_name = "probe.receipt.json" if kind == "static" else "probe.crabc-link.json"
        receipt_path = link_directory / receipt_name
        driver = product / "bin" / ("crabc-cc" if kind == "static" else "crabc-cc-dynamic")
        recorded_driver = SOURCE_MOUNT / driver.relative_to(ROOT)
        argv = [str(recorded_driver), "-static" if kind == "static" else "--dynamic-non-pie"]
        if kind == "static":
            argv.extend(["--link-receipt", receipt_name])
        argv.extend([str(alloca_object_recorded), "-o", str(recorded(executable))])
        link_command = command(link_directory, "link", argv,
                                previous_link["raw"]["command"] if replay else None)
        require(link_command["returncode"] == 0, f"selected alloca {kind} product link failed")
        output_record = object_file(executable,
                                    previous_link["raw"]["output"] if replay else None,
                                    f"selected alloca {kind} linked output")
        require(output_record["path"] == executable.relative_to(boundary_output).as_posix(),
                f"selected alloca {kind} linked output path differs")
        receipt_value = read_json_object(receipt_path, f"selected alloca {kind} link receipt")
        resolved_linker = receipt_value.get("resolved_linker")
        require(isinstance(resolved_linker, Mapping)
                and {key: resolved_linker.get(key) for key in ("path", "sha256")}
                    == {key: owned_linker.get(key) for key in ("path", "sha256")},
                f"selected alloca {kind} linker identity differs")
        if not replay:
            product_evidence.validate_link(product, alloca_object_path, executable, receipt_path, form)
        receipt_join = product_evidence.validate_retained_link(
            ROOT, str(SOURCE_MOUNT), product, alloca_object_path, executable, receipt_path,
            form, {key: owned_linker[key] for key in ("path", "sha256")},
        )
        receipt_join["product"] = products[kind]["root"]
        alloca_links.append({"linkage": kind, "returncode": link_command["returncode"],
                             "raw": {"command": link_command, "output": output_record,
                                     "receipt": receipt_join}})

    alloca_observation = {
        "header": "alloca.h",
        "profile": "c11-gnu",
        "compiler": copy.deepcopy(dict(compiler)),
        "qual_type": _selected_callable_declaration_types()["alloca"],
        "undefined_symbols": alloca_undefined,
        "relocation_symbols": alloca_external_relocations,
        "links": alloca_links,
        "raw": alloca_raw,
    }
    seqbuf_jobs = []
    previous_jobs = previous_seqbuf["jobs"] if replay else []
    require(not replay or isinstance(previous_jobs, list) and len(previous_jobs) == 4,
            "retained seqbuf_dump consumer job roster differs")
    seqbuf_types = _selected_callable_declaration_types()["seqbuf_dump"]
    for tree in ("candidate", "reference"):
        header_root = (_installed_product_header_root(static_product) if tree == "candidate"
                       else Path("/opt/musl-1.2.6/include"))
        tree_jobs = {}
        for language_index, (language, profile_name, symbol) in enumerate((
            ("c", "c11-gnu", "seqbuf_dump"),
            ("cxx", "cxx17-gnu", "_Z11seqbuf_dumpv"),
        )):
            index = (0 if tree == "candidate" else 2) + language_index
            previous_job = previous_jobs[index] if replay else None
            if replay:
                previous_job = _exact_keys(previous_job, {"tree", "header", "language", "profile", "qual_type",
                                                          "definition_symbol", "consumer_undefined_symbol",
                                                          "same_language_link", "opposite_language_link", "raw"},
                                           f"retained seqbuf_dump consumer job {index}")
            declaration_source = "#include <sys/soundcard.h>\nvoid seqbuf_dump(void) {}\n"
            consumer_source = ("#include <sys/soundcard.h>\n"
                               "void (*callback_address)(void) = SEQ_DUMPBUF;\n")
            raw_previous = previous_job["raw"] if replay else None
            raw_previous = _exact_keys(raw_previous, {"definition_source", "definition_object", "definition_compile",
                                                      "definition_symbols", "definition_relocations", "consumer_source",
                                                      "consumer_object", "consumer_compile", "consumer_symbols",
                                                      "consumer_relocations"},
                                       f"retained seqbuf_dump raw job {index}") if replay else None
            definition = collect_object(
                tree=tree, profile_name=profile_name, role="definition", source_text=declaration_source,
                previous={"source": raw_previous["definition_source"], "object": raw_previous["definition_object"],
                          "compile": raw_previous["definition_compile"], "symbols": raw_previous["definition_symbols"],
                          "relocations": raw_previous["definition_relocations"]} if replay else None,
                header_root=header_root,
            )
            consumer = collect_object(
                tree=tree, profile_name=profile_name, role="consumer", source_text=consumer_source,
                previous={"source": raw_previous["consumer_source"], "object": raw_previous["consumer_object"],
                          "compile": raw_previous["consumer_compile"], "symbols": raw_previous["consumer_symbols"],
                          "relocations": raw_previous["consumer_relocations"]} if replay else None,
                header_root=header_root,
            )
            definitions = [row for row in definition["symbols"]
                           if row["name"] == symbol and row["section"] != "UND"]
            require(len(definitions) == 1 and definitions[0]["type"] == "FUNC"
                    and definitions[0]["binding"] == "GLOBAL" and definitions[0]["visibility"] == "DEFAULT",
                    f"seqbuf_dump consumer definition differs: {tree}:{profile_name}")
            consumer_undefined = sorted({row["name"] for row in consumer["symbols"]
                                         if row["binding"] in {"GLOBAL", "WEAK"}
                                         and row["section"] == "UND" and row["name"]})
            require(consumer_undefined == [symbol]
                    and any(row["symbol"] == symbol for row in consumer["relocations"]),
                    f"seqbuf_dump consumer callback reference differs: {tree}:{profile_name}")
            tree_jobs[profile_name] = {
                "tree": tree,
                "language": language,
                "profile": profile_name,
                "symbol": symbol,
                "previous": previous_job,
                "raw_previous": raw_previous,
                "definition": definition,
                "consumer": consumer,
            }
        for language, profile_name, symbol in (("c", "c11-gnu", "seqbuf_dump"),
                                                ("cxx", "cxx17-gnu", "_Z11seqbuf_dumpv")):
            index = len(seqbuf_jobs)
            job = tree_jobs[profile_name]
            previous_job = job["previous"]
            link_observations = {}
            for link_kind, provider_profile, expected_undefined in (
                ("same_language_link", profile_name, []),
                ("opposite_language_link", "cxx17-gnu" if language == "c" else "c11-gnu", [symbol]),
            ):
                link_name = "same" if link_kind == "same_language_link" else "opposite"
                link_directory = directory(selected_root / "seqbuf_dump" / tree / profile_name / link_name)
                provider_key = (tree, provider_profile)
                previous_link = previous_job[link_kind] if replay else None
                if replay:
                    previous_link = _exact_keys(previous_link, {"returncode", "undefined_symbols", "raw"},
                                                f"retained seqbuf_dump {link_name} link")
                    previous_raw = _exact_keys(previous_link["raw"], {"command", "output", "symbols", "relocations"},
                                               f"retained seqbuf_dump {link_name} raw link")
                else:
                    previous_raw = None
                provider_object = tree_jobs[provider_profile]["definition"]["path"]
                linked_object = link_directory / "linked.o"
                recorded_consumer = recorded(job["consumer"]["path"])
                recorded_provider = recorded(provider_object)
                recorded_linked = recorded(linked_object)
                link_command = command(
                    link_directory,
                    "link",
                    [linker, "-r", str(recorded_consumer), str(recorded_provider), "-o", str(recorded_linked)],
                    previous_raw["command"] if replay else None,
                )
                require(link_command["returncode"] == 0,
                        f"seqbuf_dump {link_name} consumer link failed: {tree}:{profile_name}")
                linked_record = object_file(linked_object, previous_raw["output"] if replay else None,
                                            f"seqbuf_dump {link_name} linked object")
                linked_symbols = command(link_directory, "symbols",
                                         [readelf, "-sW", str(recorded_linked)],
                                         previous_raw["symbols"] if replay else None)
                linked_relocations = command(link_directory, "relocations",
                                             [readelf, "-rW", str(recorded_linked)],
                                             previous_raw["relocations"] if replay else None)
                require(linked_symbols["returncode"] == linked_relocations["returncode"] == 0,
                        f"seqbuf_dump {link_name} ELF inspection failed")
                linked_rows = parse_symbol_table(output_text(linked_symbols, "seqbuf_dump linked symbols"))
                undefined = sorted({row["name"] for row in linked_rows
                                    if row["binding"] in {"GLOBAL", "WEAK"}
                                    and row["section"] == "UND" and row["name"]})
                require(undefined == expected_undefined,
                        f"seqbuf_dump {link_name} consumer linkage differs: {tree}:{profile_name}")
                link_observations[link_kind] = {
                    "returncode": link_command["returncode"],
                    "undefined_symbols": undefined,
                    "raw": {"command": link_command, "output": linked_record,
                            "symbols": linked_symbols, "relocations": linked_relocations},
                }
            seqbuf_jobs.append({
                "tree": tree,
                "header": "sys/soundcard.h",
                "language": language,
                "profile": profile_name,
                "qual_type": seqbuf_types[tree][language],
                "definition_symbol": symbol,
                "consumer_undefined_symbol": symbol,
                "same_language_link": link_observations["same_language_link"],
                "opposite_language_link": link_observations["opposite_language_link"],
                "raw": {
                    "definition_source": job["definition"]["raw"]["source"],
                    "definition_object": job["definition"]["raw"]["object"],
                    "definition_compile": job["definition"]["raw"]["compile"],
                    "definition_symbols": job["definition"]["raw"]["symbols"],
                    "definition_relocations": job["definition"]["raw"]["relocations"],
                    "consumer_source": job["consumer"]["raw"]["source"],
                    "consumer_object": job["consumer"]["raw"]["object"],
                    "consumer_compile": job["consumer"]["raw"]["compile"],
                    "consumer_symbols": job["consumer"]["raw"]["symbols"],
                    "consumer_relocations": job["consumer"]["raw"]["relocations"],
                },
            })
    result = _selected_callable_boundary_summary(
        deferred,
        products,
        compiler,
        alloca_observation,
        {"jobs": seqbuf_jobs},
        provider_rows,
        raw_provider_observations,
        retained=retained,
    )
    return result


def _cpp_linkage_evidence(
    output: Path, plans: Sequence[Mapping[str, Any]], *, tools: Mapping[str, Any],
    resource_include: str, static_product: Path, dynamic_product: Path,
    timeout_seconds: float, deferred: Mapping[str, Any] | None = None,
    retained: Mapping[str, Any] | None = None,
    selected_retained: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect or replay the same finite oracle controls and owned bridge links.

    Replay never executes a driver or inspector. It rehashes the exact supplied
    products, uses the existing owned-link receipt reader, and reconstructs
    each final pointer join from retained physical ELF bytes.
    """
    replay = retained is not None
    boundary_output = output / "reviewed-cpp-linkage"
    if not replay:
        boundary_output.mkdir()
    _physical_path(boundary_output, "reviewed linkage evidence", directory=True)
    recorded_output = Path(_collector_output_path(boundary_output))
    selected = _cpp_boundary_plans(plans)
    expected_fields = {"classification", "jobs", "links", "oracle_inputs", "products", "raw", "tools"}
    if replay:
        retained = _exact_keys(retained, expected_fields, "reviewed linkage evidence")
    profiles = _profile_records()
    static_product = _physical_path(static_product, "reviewed static product", directory=True)
    dynamic_product = _physical_path(dynamic_product, "reviewed dynamic product", directory=True)
    products = {}
    for kind, path in (("static", static_product), ("dynamic", dynamic_product)):
        path = _physical_path(path, f"reviewed {kind} product", directory=True)
        require(path.is_relative_to(ROOT / ".work"), "reviewed product escapes checkout work root")
        manifest = path / "share/crabc/manifest.json"
        products[kind] = {"root": str(SOURCE_MOUNT / path.relative_to(ROOT)),
                          "manifest": _external_identity(manifest, f"reviewed {kind} product manifest")}
        products[kind]["manifest"]["path"] = str(SOURCE_MOUNT / manifest.relative_to(ROOT))
        try:
            elf_facts.installed_header_tree_digest(path / "usr/include")
        except (ValueError, OSError, abi_inventory.InventoryError) as error:
            raise NativeDeclarationAbiError(f"reviewed {kind} installed header tree rejected: {error}") from error
    if replay:
        require(strict_equal(retained["products"], products), "reviewed supplied product identity differs")

    def command(directory: Path, label: str, argv: list[str], previous: object = None) -> dict[str, Any]:
        relative = directory.relative_to(boundary_output)
        recorded_directory = recorded_output / relative
        environment = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
                       "TMPDIR": str(recorded_directory), "TZ": "UTC"}
        if replay:
            result = _validate_command_record(boundary_output, previous, expected_argv=argv,
                                             expected_cwd=str(recorded_directory),
                                             expected_environment=environment, label=label)
            _require_command_artifact_paths(result, relative, label)
            return result
        return _capture_command(boundary_output, directory, label, argv, cwd=directory,
                                environment=environment, timeout_seconds=timeout_seconds)

    tool_directory = boundary_output / "tools"
    if not replay:
        tool_directory.mkdir()
    extra_tools = {}
    for requested in ("ar", "ld"):
        if replay:
            item = _exact_keys(retained["tools"].get(requested), {"identity", "version"}, f"reviewed {requested} tool")
            identity = _validate_tool_identity(item["identity"], f"reviewed {requested} identity", retained=True)
            descriptor = _validate_artifact_descriptor(boundary_output, identity["retained"], f"reviewed {requested} bytes")
            require(descriptor["path"] == f"tools/{requested}" and all(identity[key] == descriptor[key]
                    for key in ("mode", "sha256", "size")), "reviewed tool byte seal differs")
        else:
            executable = shutil.which(requested, path="/usr/bin:/bin")
            require(executable is not None, f"reviewed {requested} tool is unavailable")
            identity = _retain_tool_identity(boundary_output, Path(executable).resolve(), tool_directory / requested,
                                             f"reviewed {requested} tool")
        version = command(tool_directory, requested + "-version", [identity["path"], "--version"],
                          retained["tools"][requested]["version"] if replay else None)
        require(version["returncode"] == 0, "reviewed linker tool version query failed")
        extra_tools[requested] = {"identity": identity, "version": version}

    oracle_inputs = {}
    input_directory = boundary_output / "inputs"
    if not replay:
        input_directory.mkdir()
    for key, source in (("static", "/opt/musl-1.2.6/lib/libc.a"),
                        ("shared", "/opt/musl-1.2.6/lib/libc.so"),
                        ("marker", "/opt/musl-1.2.6/.crabc-oracle")):
        destination = input_directory / key
        if replay:
            item = _exact_keys(retained["oracle_inputs"].get(key), {"source", "retained"}, "reviewed oracle input")
            require(item["source"] == source, "reviewed oracle input source differs")
            descriptor = _validate_artifact_descriptor(boundary_output, item["retained"], "reviewed oracle bytes")
            require(descriptor["path"] == f"inputs/{key}", "reviewed oracle retained path differs")
        else:
            _physical_path(Path(source), "pinned oracle input", directory=False)
            shutil.copy2(source, destination, follow_symlinks=False)
            descriptor = _artifact_identity(boundary_output, destination, "reviewed oracle bytes")
        oracle_inputs[key] = {"source": source, "retained": descriptor}
    callable_inventory.require_pinned_musl_marker_text(_decode_raw_text(input_directory / "marker", "reviewed oracle marker"))
    readelf = tools["readelf"]["identity"]["path"]
    raw = {}
    inventory_commands = {
        "archive-members": [extra_tools["ar"]["identity"]["path"], "t", str(recorded_output / "inputs/static")],
        "archive-symbols": [readelf, "-sW", str(recorded_output / "inputs/static")],
        "archive-headers": [readelf, "-hW", str(recorded_output / "inputs/static")],
        "archive-sections": [readelf, "-SW", str(recorded_output / "inputs/static")],
        "shared-symbols": [readelf, "--dyn-syms", "--wide", str(recorded_output / "inputs/shared")],
        "candidate-archive-members": [extra_tools["ar"]["identity"]["path"], "t",
                                      products["static"]["root"] + "/usr/lib/libc.a"],
        "candidate-archive-symbols": [readelf, "-sW", products["static"]["root"] + "/usr/lib/libc.a"],
        "candidate-archive-headers": [readelf, "-hW", products["static"]["root"] + "/usr/lib/libc.a"],
        "candidate-archive-sections": [readelf, "-SW", products["static"]["root"] + "/usr/lib/libc.a"],
        "candidate-shared-symbols": [readelf, "--dyn-syms", "--wide", products["dynamic"]["root"] + "/usr/lib/libc.so"],
    }
    for label, argv in inventory_commands.items():
        raw[label] = command(input_directory, label, argv, retained["raw"].get(label) if replay else None)
        require(raw[label]["returncode"] == 0, "reviewed oracle provider inspection failed")
    def stdout(record: Mapping[str, Any]) -> str:
        return _decode_raw_text(boundary_output / record["stdout"]["path"], "reviewed raw output")
    members = abi_inventory.parse_archive_members(stdout(raw["archive-members"]))
    reference_provider_inventory = {
        "static": oracle_static_provider_rows(
            members,
            stdout(raw["archive-headers"]),
            stdout(raw["archive-sections"]),
            stdout(raw["archive-symbols"]),
            str(recorded_output / "inputs/static"),
        ),
        "shared": abi_inventory.parse_dynamic_symbol_rows(stdout(raw["shared-symbols"])),
    }
    candidate_members = abi_inventory.parse_archive_members(stdout(raw["candidate-archive-members"]))
    candidate_archive = products["static"]["root"] + "/usr/lib/libc.a"
    candidate_provider_inventory = {
        "static": oracle_static_provider_rows(
            candidate_members,
            stdout(raw["candidate-archive-headers"]),
            stdout(raw["candidate-archive-sections"]),
            stdout(raw["candidate-archive-symbols"]),
            candidate_archive,
        ),
        "shared": abi_inventory.parse_dynamic_symbol_rows(stdout(raw["candidate-shared-symbols"])),
    }
    if replay:
        require(isinstance(retained["jobs"], list) and len(retained["jobs"]) == len(selected),
                "reviewed linkage probe job roster differs")
        jobs = [_validate_job(boundary_output, recorded_output, item, plan, index, tools=tools,
                              profiles=profiles, resource_include=resource_include, executable_probe=True)
                for index, (item, plan) in enumerate(zip(retained["jobs"], selected, strict=True))]
    else:
        jobs = [_collect_one_object_job(boundary_output, index, plan, tools=tools, profiles=profiles,
                                        resource_include=Path(resource_include), timeout_seconds=timeout_seconds,
                                        executable_probe=True) for index, plan in enumerate(selected)]
    classification = reviewed_cpp_linkage_boundary(selected, jobs, reference_provider_inventory)
    _candidate_bridge_provider(candidate_provider_inventory["static"], classification["candidate_symbol"], "static")
    classification["candidate_shared_provider"] = _candidate_bridge_provider(
        candidate_provider_inventory["shared"], classification["candidate_symbol"], "shared")
    if replay:
        require(strict_equal(retained["classification"], classification), "reviewed oracle disposition differs")
    links = []
    previous_links = iter(retained["links"] if replay else [])
    lld_identity = None
    for index, (plan, job) in enumerate(zip(selected, jobs, strict=True)):
        candidate = plan["tree"] == "candidate"
        forms = REVIEWED_CPP_LINKAGE_BOUNDARY["candidate_linkages" if candidate else "reference_linkages"]
        for form in forms:
            directory = boundary_output / "links" / plan["tree"] / plan["profile"] / form
            if not replay:
                directory.mkdir(parents=True)
            recorded_directory = recorded_output / directory.relative_to(boundary_output)
            executable = directory / "probe"
            object_path = boundary_output / job["object"]["path"]
            recorded_object = str(recorded_output / job["object"]["path"])
            recorded_executable = str(recorded_directory / "probe")
            negative = not candidate and plan["profile"] in REVIEWED_CPP_LINKAGE_BOUNDARY["profiles"]
            previous = next(previous_links, None) if replay else None
            if replay:
                previous = _exact_keys(previous, {"job_index", "linkage", "command", "output", "receipt", "join", "inspection"},
                                       "reviewed linkage control")
                require(previous["job_index"] == index and previous["linkage"] == form,
                        "reviewed linkage control identity differs")
            if candidate:
                product = static_product if form.startswith("static") else dynamic_product
                product = _physical_path(product, "reviewed link product", directory=True)
                driver = product / "bin" / ("crabc-cc" if form.startswith("static") else "crabc-cc-dynamic")
                argv = [str(SOURCE_MOUNT / driver.relative_to(ROOT)), ("-" if form.startswith("static") else "--dynamic-") + form]
                if form.startswith("static"):
                    argv.extend(["--link-receipt", "probe.receipt.json"])
                argv.extend([recorded_object, "-o", recorded_executable])
                receipt = directory / ("probe.receipt.json" if form.startswith("static") else "probe.crabc-link.json")
            else:
                argv = [extra_tools["ld"]["identity"]["path"], "--no-demangle", "--no-undefined", "-e", "main"]
                if form == "static":
                    argv.append("-static")
                argv.extend([recorded_object, str(recorded_output / "inputs" / form), "-o", recorded_executable])
            linked = command(directory, "link", argv, previous["command"] if replay else None)
            record = {"job_index": index, "linkage": form, "command": linked,
                      "output": None, "receipt": None, "join": None, "inspection": None}
            if negative:
                diagnostic = _decode_raw_text(boundary_output / linked["stderr"]["path"], "reviewed negative link diagnostic")
                targets = re.findall(r"undefined reference to [`']([^']+)'", diagnostic)
                require(linked["returncode"] == 1 and targets and set(targets) == {classification["reference_symbol"]}
                        and not executable.exists(), "reviewed oracle C++ negative link did not fail for its exact missing provider")
            else:
                require(linked["returncode"] == 0, "reviewed C bridge ordinary link failed")
                record["output"] = (_validate_artifact_descriptor(boundary_output, previous["output"], "reviewed linked output")
                                    if replay else _artifact_identity(boundary_output, executable, "reviewed linked output"))
                require(record["output"]["path"] == executable.relative_to(boundary_output).as_posix(),
                        "reviewed linked output path differs")
                inspection = {}
                for label, flags in (("symbols", ["-sW"]), ("sections", ["-SW"])):
                    inspection[label] = command(directory, label, [readelf, *flags, recorded_executable],
                                                 previous["inspection"][label] if replay else None)
                    require(inspection[label]["returncode"] == 0, "reviewed linked output inspection failed")
                record["inspection"] = inspection
                record["join"] = physical_reference_join(executable, stdout(inspection["symbols"]),
                                                          stdout(inspection["sections"]), static=form.startswith("static"))
                if candidate:
                    receipt_record = read_json_object(receipt, "reviewed owned link receipt")
                    resolved_linker = receipt_record["resolved_linker"]
                    if lld_identity is None:
                        if replay:
                            lld_identity = _validate_tool_identity(retained["tools"]["lld"], "reviewed owned linker", retained=True)
                            sealed = _validate_artifact_descriptor(boundary_output, lld_identity["retained"], "reviewed owned linker bytes")
                            require(sealed["path"] == "tools/lld" and all(lld_identity[key] == sealed[key]
                                    for key in ("mode", "sha256", "size")), "reviewed owned linker byte seal differs")
                        else:
                            lld_identity = _retain_tool_identity(boundary_output, Path(resolved_linker["path"]),
                                                               tool_directory / "lld", "reviewed owned linker")
                    linker_seal = {key: lld_identity[key] for key in ("path", "sha256")}
                    require(resolved_linker == linker_seal, "reviewed owned linker changed between links")
                    if not replay:
                        product_evidence.validate_link(product, object_path, executable, receipt, form)
                    joined_receipt = product_evidence.validate_retained_link(ROOT, str(SOURCE_MOUNT), product, object_path,
                                                                             executable, receipt, form, linker_seal)
                    joined_receipt["product"] = products["static" if form.startswith("static") else "dynamic"]["root"]
                    record["receipt"] = joined_receipt
            if replay:
                require(strict_equal(record, previous), "reviewed physical linkage control differs")
            links.append(record)
    if replay:
        require(next(previous_links, None) is None, "reviewed linkage control roster has extra rows")
        require(set(retained["tools"]) == {"ar", "ld", "lld"} and set(retained["raw"]) == set(raw)
                and set(retained["oracle_inputs"]) == set(oracle_inputs), "reviewed linkage input roster differs")
    extra_tools["lld"] = lld_identity
    raw_provider_observations = {
        "candidate": {
            "static": {"members": raw["candidate-archive-members"]["stdout"],
                       "headers": raw["candidate-archive-headers"]["stdout"],
                       "sections": raw["candidate-archive-sections"]["stdout"],
                       "symbols": raw["candidate-archive-symbols"]["stdout"]},
            "shared": {"symbols": raw["candidate-shared-symbols"]["stdout"]},
        },
        "reference": {
            "static": {"members": raw["archive-members"]["stdout"],
                       "headers": raw["archive-headers"]["stdout"],
                       "sections": raw["archive-sections"]["stdout"],
                       "symbols": raw["archive-symbols"]["stdout"]},
            "shared": {"symbols": raw["shared-symbols"]["stdout"]},
        },
    }
    selected_boundaries = _selected_callable_boundary_evidence(
        boundary_output,
        recorded_output,
        static_product=static_product,
        dynamic_product=dynamic_product,
        products=_selected_callable_product_seal(static_product, dynamic_product),
        deferred={} if deferred is None else deferred,
        tools=tools,
        extra_tools=extra_tools,
        resource_include=resource_include,
        timeout_seconds=timeout_seconds,
        provider_rows={"candidate": candidate_provider_inventory, "reference": reference_provider_inventory},
        raw_provider_observations=raw_provider_observations,
        command=command,
        owned_linker=lld_identity,
        retained=selected_retained,
    )
    return {"classification": classification, "jobs": jobs, "links": links, "oracle_inputs": oracle_inputs,
            "products": products, "raw": raw, "tools": extra_tools,
            "selected_callable_boundaries": selected_boundaries}


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


def _validate_tool_identity(
    value: object,
    description: str,
    *,
    retained: bool,
) -> dict[str, Any]:
    expected = {"mode", "path", "sha256", "size"}
    if retained:
        expected.add("retained")
    raw = _exact_keys(value, expected, description)
    path = _string(raw["path"], f"{description}.path")
    require(Path(path).is_absolute() and Path(path).as_posix() == path, f"{description}.path is not absolute")
    digest = _string(raw["sha256"], f"{description}.sha256")
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"{description}.sha256 is invalid")
    mode = _nonnegative_integer(raw["mode"], f"{description}.mode")
    require(bool(mode & 0o111), f"{description}.mode is not executable")
    size = _positive_integer(raw["size"], f"{description}.size")
    normalized = {"mode": mode, "path": path, "sha256": digest, "size": size}
    if retained:
        normalized["retained"] = raw["retained"]
    return normalized


def _validate_resource_tree(
    output: Path,
    value: object,
    *,
    header_tools: Mapping[str, Any],
) -> dict[str, Any]:
    raw = _exact_keys(value, {"path", "records"}, "retained compiler resource tree")
    path = _string(raw["path"], "retained compiler resource tree path")
    require(Path(path).is_absolute() and Path(path).as_posix() == path, "retained compiler resource tree path is invalid")
    require(path == header_tools.get("resource_include"),
            "retained compiler resource tree differs from the replayed public-header envelope")
    raw_header_records = header_tools.get("resource_headers")
    require(isinstance(raw_header_records, list), "header compiler resource roster is invalid")
    header_records: dict[str, Mapping[str, Any]] = {}
    for ordinal, item in enumerate(raw_header_records):
        require(isinstance(item, Mapping), f"header compiler resource record {ordinal} is invalid")
        relative = _safe_relative(item.get("path"), f"header compiler resource record {ordinal}.path")
        digest = _string(item.get("sha256"), f"header compiler resource record {ordinal}.sha256")
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"header compiler resource record {ordinal}.sha256 is invalid")
        size = _nonnegative_integer(item.get("size"), f"header compiler resource record {ordinal}.size")
        require(relative not in header_records, f"header compiler resource record repeats: {relative}")
        header_records[relative] = {"sha256": digest, "size": size}
    records = raw["records"]
    require(isinstance(records, list) and bool(records), "retained compiler resource tree records are invalid")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    observed_files: set[str] = set()
    for index, item in enumerate(records):
        require(isinstance(item, Mapping), f"retained compiler resource tree record {index} is invalid")
        kind = item.get("kind")
        if kind == "directory":
            record = _exact_keys(item, {"kind", "mode", "path"}, f"retained compiler resource tree directory {index}")
        elif kind == "file":
            record = _exact_keys(item, {"kind", "mode", "path", "retained", "sha256", "size"},
                                 f"retained compiler resource tree file {index}")
            digest = _string(record["sha256"], f"retained compiler resource tree file {index}.sha256")
            require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                    f"retained compiler resource tree file {index}.sha256 is invalid")
            size = _nonnegative_integer(record["size"], f"retained compiler resource tree file {index}.size")
        else:
            raise NativeDeclarationAbiError(f"retained compiler resource tree record {index}.kind is invalid")
        relative = _safe_relative(record["path"], f"retained compiler resource tree record {index}.path")
        require(relative not in seen, f"retained compiler resource tree path repeats: {relative}")
        seen.add(relative)
        mode = _nonnegative_integer(record["mode"], f"retained compiler resource tree record {index}.mode")
        if kind == "file":
            expected_path = (Path("inputs") / "tools" / "clang-resource" / relative).as_posix()
            retained = _validate_artifact_descriptor(
                output, record["retained"], f"retained compiler resource tree file {relative}",
            )
            require(retained["path"] == expected_path, f"retained compiler resource tree file {relative} path differs")
            require(retained["mode"] == mode and retained["sha256"] == digest and retained["size"] == size,
                    f"retained compiler resource tree file {relative} bytes differ")
            expected = header_records.get(relative)
            if expected is not None:
                require(digest == expected["sha256"] and size == expected["size"],
                        f"retained compiler resource file differs from the replayed public-header envelope: {relative}")
            observed_files.add(relative)
        normalized.append(copy.deepcopy(dict(record)))
    require([record["path"] for record in normalized] == sorted(record["path"] for record in normalized),
            "retained compiler resource tree records are not sorted")
    require(set(header_records).issubset(observed_files),
            "header compiler resource file is absent from retained ordinary compiler resource tree")
    return {"path": path, "records": normalized}


def _validate_tools(
    output: Path,
    value: object,
    collector_output: Path,
    timeout_seconds: float,
    *,
    header_tools: Mapping[str, Any],
) -> dict[str, Any]:
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
        identity = _validate_tool_identity(record["identity"], f"retained {name} tool identity", retained=name == "readelf")
        if name == "clang":
            _require_header_clang_identity(identity, header_tools)
        else:
            retained = _validate_artifact_descriptor(output, identity["retained"], "retained readelf executable")
            require(retained["path"] == "inputs/tools/readelf", "retained readelf executable path differs")
            require(
                retained["mode"] == identity["mode"]
                and retained["sha256"] == identity["sha256"]
                and retained["size"] == identity["size"],
                "retained readelf executable bytes differ",
            )
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
        normalized[name] = {
            "identity": {key: identity[key] for key in ("mode", "path", "sha256", "size")},
            "requested": name,
            "version": version,
        }
        if name == "clang":
            normalized[name]["resource_include"] = _validate_resource_tree(
                output, record["resource_include"], header_tools=header_tools,
            )
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
    reviewed_cpp_linkage_boundary: Mapping[str, Any] | None = None,
    selected_callable_boundaries: Mapping[str, Any] | None = None,
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
        "reviewed_cpp_linkage_boundary": copy.deepcopy(reviewed_cpp_linkage_boundary),
        "selected_callable_boundaries": copy.deepcopy(selected_callable_boundaries),
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
    static_product: Path | None = None,
    dynamic_product: Path | None = None,
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
        account, plans, callable_plan_source, header_tools = derive_callable_plan(header_report)
        layout = _record_layout_projection()
        tools, resource_include = _collection_tools(output, timeout_seconds, header_tools=header_tools)
        require((static_product is None) == (dynamic_product is None), "both reviewed owned products must be supplied together")
        reviewed_boundary = None
        selected_boundaries = None
        if static_product is not None and dynamic_product is not None:
            boundary_evidence = _cpp_linkage_evidence(
                output, plans, tools=tools, resource_include=str(resource_include),
                static_product=static_product, dynamic_product=dynamic_product,
                timeout_seconds=timeout_seconds,
                deferred=_selected_deferred_owner_map(account),
            )
            selected_boundaries = boundary_evidence.pop("selected_callable_boundaries")
            reviewed_boundary = boundary_evidence
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
            reviewed_cpp_linkage_boundary=reviewed_boundary,
            selected_callable_boundaries=selected_boundaries,
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
    executable_probe: bool = False,
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
    require(_decode_raw_text(output / source_record["path"], f"retained ordinary declaration source {ordinal}") == generated_source(plan, executable_probe=executable_probe),
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
        executable_probe=executable_probe,
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
    header_envelope: Mapping[str, Any] | None = None,
    static_product: Path | None = None,
    dynamic_product: Path | None = None,
) -> dict[str, Any]:
    """Replay a declaration ABI report without invoking a native tool.

    ``header_report`` is an explicit host mapping for the one retained public
    header envelope.  Its bytes must match the immutable collector input; the
    host reader never treats the collector's `/inputs/...` path as authority.
    A selection caller may pass the exact envelope it has already replayed to
    ``header_envelope`` so this reader does not replay that raw receipt again.
    """
    report_path = _physical_path(report_path, "native declaration ABI report", directory=False)
    require(report_path.name == "report.json", "native declaration ABI report name differs")
    output = _physical_path(report_path.parent, "native declaration ABI evidence directory", directory=True)
    require(output.parent == WORK_DIRECTORY, "native declaration ABI evidence directory differs")
    report = read_json_object(report_path, "native declaration ABI report")
    expected_keys = {
        "callable_plan", "callable_plan_source", "execution", "header_declaration_report", "inputs", "jobs",
        "oracle", "record_layout_projection", "schema", "status", "summary", "target",
        "reviewed_cpp_linkage_boundary", "selected_callable_boundaries",
    }
    require(set(report) == expected_keys, "native declaration ABI report fields differ")
    require(report["schema"] == SCHEMA and report["target"] == TARGET and report["oracle"] == ORACLE,
            "native declaration ABI report identity differs")
    collector_output, execution = _validate_execution(output, report["execution"])
    inputs = _exact_keys(report["inputs"], {"source_snapshots", "tools"}, "native declaration ABI inputs")
    source_snapshots = _validate_source_snapshots(output, inputs["source_snapshots"])
    supplied_header_report = _physical_path(header_report, "supplied header declaration report", directory=False)
    header_identity = _validate_collector_header_identity(report["header_declaration_report"], supplied_header_report)
    account, plans, callable_plan_source, header_tools = derive_callable_plan(
        supplied_header_report,
        header_envelope=header_envelope,
    )
    tools = _validate_tools(
        output, inputs["tools"], collector_output, execution["timeout_seconds"], header_tools=header_tools,
    )
    require(strict_equal(report["callable_plan"], plans), "retained callable object plan differs")
    require(strict_equal(report["callable_plan_source"], callable_plan_source), "retained callable plan source differs")
    layout = _record_layout_projection()
    require(strict_equal(report["record_layout_projection"], layout), "retained record-layout projection differs")
    raw_jobs = report["jobs"]
    require(isinstance(raw_jobs, list) and len(raw_jobs) == len(plans), "retained ordinary declaration job roster differs")
    profiles = _profile_records()
    resource_path = tools["clang"]["resource_include"]["path"]
    require((static_product is None) == (dynamic_product is None), "both reviewed owned products must be supplied together")
    boundary = report["reviewed_cpp_linkage_boundary"]
    if boundary is not None:
        require(static_product is not None and dynamic_product is not None,
                "reviewed linkage replay requires both exact supplied owned products")
        selected_boundary = report["selected_callable_boundaries"]
        require(isinstance(selected_boundary, Mapping), "selected callable boundary replay receipt is absent")
        rebuilt = _cpp_linkage_evidence(
            output, plans, tools=tools, resource_include=resource_path,
            static_product=static_product, dynamic_product=dynamic_product,
            timeout_seconds=execution["timeout_seconds"],
            deferred=_selected_deferred_owner_map(account),
            retained=boundary,
            selected_retained=selected_boundary,
        )
        rebuilt_selected = rebuilt.pop("selected_callable_boundaries")
        require(strict_equal(boundary, rebuilt), "retained reviewed linkage boundary differs")
        require(strict_equal(selected_boundary, rebuilt_selected), "retained selected callable boundary differs")
    else:
        require(report["selected_callable_boundaries"] is None,
                "selected callable boundary lacks its provider and consumer inputs")
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
        "selected_callable_boundaries": copy.deepcopy(report["selected_callable_boundaries"]),
        "report": report,
        "summary": summary,
    }


def validation_result(report_path: Path, replayed: Mapping[str, Any]) -> dict[str, Any]:
    """Render a compact host-side replay receipt without duplicating raw jobs."""
    report_path = _physical_path(report_path, "native declaration ABI report", directory=False)
    require(isinstance(replayed, Mapping) and set(replayed) == {
        "callable_plan", "execution", "header_declaration_report", "record_layout_projection",
        "selected_callable_boundaries", "report", "summary"
    }, "native declaration ABI replay result differs")
    return {
        "header_declaration_report": copy.deepcopy(dict(replayed["header_declaration_report"])),
        "report": _external_identity(report_path, "native declaration ABI report"),
        "schema": VALIDATION_SCHEMA,
        "selected_callable_boundaries": copy.deepcopy(replayed["selected_callable_boundaries"]),
        "status": copy.deepcopy(dict(replayed["report"]["status"])),
        "summary": copy.deepcopy(dict(replayed["summary"])),
    }


def _parse_cli(arguments: Sequence[str] | None) -> argparse.Namespace:
    raw_arguments = list(sys.argv[1:] if arguments is None else arguments)
    for option in ("--header-report", "--output", "--workers", "--timeout-seconds", "--static-product", "--dynamic-product"):
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
    parser.add_argument("--static-product", type=Path, help="exact owned static product for reviewed C/C++ bridge controls")
    parser.add_argument("--dynamic-product", type=Path, help="exact owned dynamic product for reviewed C/C++ bridge controls")
    parsed = parser.parse_args(raw_arguments)
    require((parsed.static_product is None) == (parsed.dynamic_product is None),
            "both reviewed owned products must be supplied together")
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
            static_product=parsed.static_product,
            dynamic_product=parsed.dynamic_product,
        )
        sys.stdout.write(json.dumps({"report": _artifact_identity(Path(parsed.output), Path(parsed.output) / "report.json", "native declaration ABI report")}, sort_keys=True) + "\n")
        return 0
    replayed = validate_report(parsed.validate_report, header_report=parsed.header_report,
                              static_product=parsed.static_product, dynamic_product=parsed.dynamic_product)
    sys.stdout.write(json.dumps(validation_result(parsed.validate_report, replayed), sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except NativeDeclarationAbiError as error:
        print(f"ERROR: x86 native declaration ABI: {error}", file=sys.stderr)
        raise SystemExit(1)
