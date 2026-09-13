#!/usr/bin/env python3
"""Collect and replay a measurement-only native x86 musl/owned ABI inventory.

The inventory is an observation boundary for compat.abi-differential. It does
not decide compatibility, complete a family, or promote any product. Collection
uses fixed /opt/musl-1.2.6 plus two sealed supplied owned products. Replay uses
retained raw tool output and input copies, then revalidates supplied products
and their materialization/static-preparation provenance on the host.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

import owned_posix_product_evidence as product_evidence
import owned_dynamic_qualification as dynamic_materialization


SCHEMA = "crabc.x86_64-native-abi-inventory/v1"
TARGET = "x86_64-unknown-linux-musl"
MUSL_ROOT = Path("/opt/musl-1.2.6")
STATIC_PRODUCT_PATH = Path("/inputs/static-product")
DYNAMIC_PRODUCT_PATH = Path("/inputs/dynamic-product")
STATIC_PREPARATION_PATH = Path("/inputs/static-preparation.json")
CANONICAL_WORK_ROOT = Path("/workspace/.work/x86_64")
REPORT_NAME = "report.json"
RAW_DIRECTORY = "raw"
INPUT_DIRECTORY = "inputs"
MUSL_COPY_ROOT = "inputs/musl-1.2.6"
TOOLS_COPY_ROOT = "inputs/tools"
SOURCES_COPY_ROOT = "inputs/source"
RECEIPTS_COPY_ROOT = "inputs/receipts"

TOOL_PATHS = {
    "readelf": Path("/usr/bin/readelf"),
    "nm": Path("/usr/bin/nm"),
    "ar": Path("/usr/bin/ar"),
}
TOOL_ENVIRONMENT = {
    "LC_ALL": "C",
    "LANG": "C",
    "PATH": "/usr/bin:/bin",
}
TOOL_TIMEOUT_SECONDS = 30
MUSL_REGULAR_FILES = (
    "lib/libc.so",
    "lib/libc.a",
    "lib/musl-gcc.specs",
    ".crabc-oracle",
    ".crabc-musl-gcc-specs.sha256",
)
MUSL_LOADER = "lib/ld-musl-x86_64.so.1"
MUSL_COMPILER = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
SOURCE_FILES = (
    "compat/x86_64/native_abi_inventory.py",
    "compat/x86_64/owned_posix_product_evidence.py",
    "compat/x86_64/owned_dynamic_qualification.py",
    "compat/x86_64/crabc_cc_owned_dynamic.py",
    "compat/x86_64/crabc_cc_static.py",
    "compat/x86_64/crabc_cc_dynamic.py",
    "compat/x86_64/owned_dynamic_receipt.py",
    "compat/x86_64/dynamic_product_contract.py",
    "compat/x86_64/validate_loader_libc_tls_runtime_v1.py",
    "compat/x86_64/headers_layouts_aggregate.py",
    "compat/x86_64/generated/headers_layouts_aggregate/report.json",
    "compat/x86_64/dynamic-product.toml",
    "compat/x86_64/dynamic-product-state.json",
    "compat/x86_64/loader-libc-tls-runtime-v1.toml",
    "compat/upstreams.toml",
    "docker/Dockerfile.x86_64",
    "docker/x86_64-musl-oracle-gcc",
    "scripts/dev-x86_64.sh",
)

DYNAMIC_COLUMNS = (
    "name",
    "type",
    "binding",
    "visibility",
    "version",
    "version_default",
    "size",
    "value",
    "section_index",
)
STATIC_COLUMNS = (
    "name",
    "archive_member",
    "nm_type",
    "binding",
    "value",
    "size",
)

_DYNAMIC_LINE = re.compile(
    r"^\s*(?P<number>\d+):\s+(?P<value>\S+)\s+(?P<size>\S+)\s+"
    r"(?P<symbol_type>\S+)\s+(?P<binding>\S+)\s+(?P<visibility>\S+)\s+"
    r"(?P<section>\S+)(?:\s+(?P<raw_name>\S+)"
    r"(?:\s+\((?P<version_index>[1-9][0-9]*)\))?)?\s*$"
)
_DYNAMIC_TABLE = re.compile(r"^Symbol table '\.dynsym' contains (?P<count>\d+) entr(?:y|ies):$")
_DYNAMIC_SECTION = re.compile(
    r"^Dynamic section at offset 0x[0-9A-Fa-f]+ contains (?P<count>\d+) entries:$"
)
_DYNAMIC_TABLE_HEADER = re.compile(r"^Tag\s+Type\s+Name/Value$")
_ARCHIVE_LINE = re.compile(r"^(?P<archive>.+)\[(?P<member>[^]]*)\]:\s+(?P<rest>.+)$")
_FILE_LINE = re.compile(
    r"^File:\s+(?P<archive>.+?)(?:\[(?P<bracket_member>[^]]*)\]|\((?P<paren_member>[^)]*)\))\s*$"
)
_ELF_FIELD = re.compile(r"^\s*(?P<name>[^:]+):\s*(?P<value>.*\S)\s*$")
_DYNAMIC_TAG = re.compile(r"^\s*0x[0-9A-Fa-f]+\s+\((?P<tag>[^)]+)\)\s+(?P<value>.*\S)\s*$")
_RELOCATION_TYPE = re.compile(r"\b(R_X86_64_[A-Z0-9_]+)\b")
_PROGRAM_COUNT = re.compile(r"^There are (?P<count>\d+) program headers,")
_RELOCATION_SECTION = re.compile(
    r"^Relocation section '(?P<name>[^']+)' .* contains (?P<count>\d+) entries:$"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"crabc-core-evidence@sha256:[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")


class InventoryError(RuntimeError):
    """A required inventory input, tool result, or retained record drifted."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InventoryError(message)


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _reject_symlink_components(path: Path, description: str) -> Path:
    require(".." not in path.parts, f"{description} has parent traversal")
    absolute = _absolute(path)
    current = Path(absolute.anchor)
    try:
        for component in absolute.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                raise InventoryError(f"{description} traverses a symlink: {path}")
    except OSError as error:
        raise InventoryError(f"{description} is unreadable: {path}") from error
    return absolute


def physical_directory(path: Path, description: str) -> Path:
    absolute = _reject_symlink_components(path, description)
    try:
        require(
            stat.S_ISDIR(absolute.lstat().st_mode),
            f"{description} is not a physical directory: {path}",
        )
    except OSError as error:
        raise InventoryError(f"{description} is unreadable: {path}") from error
    return absolute


def physical_regular(path: Path, description: str) -> Path:
    absolute = _reject_symlink_components(path, description)
    try:
        require(
            stat.S_ISREG(absolute.lstat().st_mode),
            f"{description} is not a physical regular file: {path}",
        )
    except OSError as error:
        raise InventoryError(f"{description} is unreadable: {path}") from error
    return absolute


def physical_executable(path: Path, description: str) -> Path:
    absolute = physical_regular(path, description)
    try:
        require(bool(absolute.lstat().st_mode & 0o111), f"{description} is not executable: {path}")
    except OSError as error:
        raise InventoryError(f"{description} is unreadable: {path}") from error
    return absolute


def sha256(path: Path) -> str:
    path = physical_regular(path, "hashed input")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise InventoryError(f"cannot hash input: {path}") from error
    return digest.hexdigest()


def file_record(path: Path, *, logical_path: str | None = None) -> dict[str, object]:
    path = physical_regular(path, "recorded input")
    details = path.lstat()
    return {
        "path": logical_path if logical_path is not None else str(path),
        "sha256": sha256(path),
        "size": details.st_size,
        "mode": stat.S_IMODE(details.st_mode),
    }


def read_json(path: Path, description: str) -> dict[str, Any]:
    path = physical_regular(path, description)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_object)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise InventoryError(f"{description} is not valid JSON: {path}") from error
    require(isinstance(value, dict), f"{description} must be a JSON object")
    return value


def require_exact_keys(value: object, expected: set[str], description: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == expected, f"{description} fields drifted")
    return value


def require_digest(value: object, actual: str, description: str) -> None:
    require(
        isinstance(value, str) and _SHA256.fullmatch(value) is not None,
        f"{description} has invalid SHA-256",
    )
    require(value == actual, f"{description} differs from physical input")


def require_empty_diagnostics(tool: str, diagnostics: str) -> None:
    require(not diagnostics, f"{tool} emitted a diagnostic and cannot describe a complete inventory")


def _split_version(raw_name: str) -> tuple[str, str | None, bool]:
    if "@@" in raw_name:
        name, version = raw_name.split("@@", 1)
        require(bool(name) and bool(version), f"invalid default dynamic symbol version: {raw_name}")
        return name, version, True
    if "@" in raw_name:
        name, version = raw_name.split("@", 1)
        require(bool(name) and bool(version), f"invalid dynamic symbol version: {raw_name}")
        return name, version, False
    return raw_name, None, False


def parse_dynamic_symbols(raw: str) -> list[dict[str, object]]:
    """Parse every public defined dynsym row without erasing version semantics."""

    records: list[dict[str, object]] = []
    expected_count: int | None = None
    row_indexes: list[int] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        table = _DYNAMIC_TABLE.match(stripped)
        if table:
            require(expected_count is None, "readelf emitted more than one dynamic symbol table")
            expected_count = int(table.group("count"))
            continue
        if stripped.startswith("Num:"):
            continue
        if re.match(r"^\d+:", stripped):
            match = _DYNAMIC_LINE.match(line)
            require(match is not None, f"malformed dynamic symbol row: {line}")
            number = match.group("number")
            value = match.group("value")
            size = match.group("size")
            symbol_type = match.group("symbol_type")
            binding = match.group("binding")
            visibility = match.group("visibility")
            section = match.group("section")
            raw_name = match.group("raw_name")
            row_indexes.append(int(number))
            if (
                section == "UND"
                or binding not in {"GLOBAL", "WEAK", "UNIQUE"}
                or visibility not in {"DEFAULT", "PROTECTED"}
            ):
                continue
            require(raw_name is not None, f"dynamic symbol row lacks a name: {line}")
            name, version, version_default = _split_version(raw_name)
            records.append({
                "name": name,
                "type": symbol_type,
                "binding": binding,
                "visibility": visibility,
                "version": version,
                "version_default": version_default,
                "size": size,
                "value": value,
                "section_index": section,
            })
            continue
        raise InventoryError(f"unrecognized dynamic symbol output: {line}")
    require(expected_count is not None, "readelf dynamic-symbol output has no symbol table")
    require(
        row_indexes == list(range(expected_count)),
        "readelf dynamic-symbol rows are missing, duplicated, reordered, or truncated",
    )
    keys = [(record["name"], record["version"], record["version_default"]) for record in records]
    require(len(keys) == len(set(keys)), "duplicate dynamic name/version/defaultness rows")
    return records


def parse_static_symbols(raw: str, *, expected_archive: str | None = None) -> list[dict[str, str]]:
    """Retain every raw nm row in command order, including duplicates."""

    records: list[dict[str, str]] = []
    for line in raw.splitlines():
        if not line:
            continue
        match = _ARCHIVE_LINE.match(line)
        require(match is not None, f"unparseable nm output: {line}")
        if expected_archive is not None:
            require(match.group("archive") == expected_archive, f"nm output names a different archive: {match.group('archive')}")
        fields = match.group("rest").split()
        require(len(fields) in {3, 4}, f"malformed nm symbol row: {line}")
        name, nm_type, value = fields[:3]
        require(len(nm_type) == 1, f"unexpected nm symbol class: {line}")
        size = fields[3] if len(fields) == 4 else "-"
        if nm_type in {"W", "V", "w", "v"}:
            binding = "WEAK"
        elif nm_type == "u":
            binding = "UNIQUE"
        elif nm_type in {"A", "B", "C", "D", "G", "I", "N", "R", "S", "T"}:
            binding = "GLOBAL"
        else:
            binding = "UNCLASSIFIED"
        records.append({
            "name": name,
            "archive_member": match.group("member"),
            "nm_type": nm_type,
            "binding": binding,
            "value": value,
            "size": size,
        })
    return records


# These opt-in projections deliberately do not feed the v1 report. A future
# collector must bind the additional commands and artifacts in its own schema;
# a successful text projection alone is not a source-bound ELF observation.
_SYMBOL_FIELD = r"(?:<[^>\n]+>:\s*[0-9]+|[^\s<>]+)"
_COMPLETE_SYMBOL_LINE = re.compile(
    r"^\s*(?P<number>[0-9]+):\s+(?P<value>[0-9a-fA-F]+)\s+"
    r"(?P<size>0x[0-9a-fA-F]+|[0-9]+)\s+"
    rf"(?P<symbol_type>{_SYMBOL_FIELD})\s+(?P<binding>{_SYMBOL_FIELD})\s+"
    rf"(?P<visibility>{_SYMBOL_FIELD})\s+"
    r"(?:(?P<other>\[<other>:\s*[0-9a-fA-F]+\])\s+)?"
    r"(?P<section>\S+)(?:\s+(?P<name>.*\S))?\s*$"
)
_SYMBOL_TABLE = re.compile(r"^Symbol table '(?P<name>[^']+)' contains (?P<count>[0-9]+) entr(?:y|ies):$")
_SYMBOL_COLUMNS = "Num: Value Size Type Bind Vis Ndx Name".split()
_SECTION_COUNT = re.compile(r"^There are (?P<count>[0-9]+) section headers, starting at offset (?P<offset>0x[0-9a-fA-F]+):$")
_SECTION_LINE = re.compile(
    r"^\s*\[\s*(?P<index>[0-9]+)\]\s+(?:(?P<name>.*?)\s+)?"
    r"(?P<type>\S+)\s+(?P<address>[0-9a-fA-F]{16})\s+"
    r"(?P<offset>[0-9a-fA-F]+)\s+(?P<size>[0-9a-fA-F]+)\s+"
    r"(?P<entry_size>[0-9a-fA-F]+)\s+(?:(?P<flags>\S+)\s+)?"
    r"(?P<link>[0-9]+)\s+(?P<info>[0-9]+)\s+(?P<alignment>[0-9]+)\s*$"
)
# These are termination/occurrence contracts for the pinned GNU readelf's
# C-locale x86-64 display, not an ELF specification or a cross-version parser.
# A tool update changing either display requires an explicit parser update and
# retained native evidence. Unknown symbol/section row metadata stays intact.
_PINNED_SECTION_FLAG_LEGEND_PREFIX = (
    "W (write), A (alloc), X (execute), M (merge), S (strings), I (info),",
    "L (link order), O (extra OS processing required), G (group), T (TLS),",
    "C (compressed), x (unknown), o (OS specific), E (exclude),",
)
_PINNED_SECTION_FLAG_LEGEND_ENDINGS = (
    "D (mbind), l (large), p (processor specific)",
    "R (retain), D (mbind), l (large), p (processor specific)",
)
_PINNED_ELF_HEADER_FIELDS = (
    "Magic", "Class", "Data", "Version", "OS/ABI", "ABI Version", "Type",
    "Machine", "Version", "Entry point address", "Start of program headers",
    "Start of section headers", "Flags", "Size of this header",
    "Size of program headers", "Number of program headers",
    "Size of section headers", "Number of section headers",
    "Section header string table index",
)


def parse_elf_symbol_tables(raw: str) -> list[dict[str, Any]]:
    """Project complete C-locale GNU readelf --wide --symbols output.

    Table and row ordinals, raw names/rows, undefined/local/hidden definitions,
    unknown kinds/bindings and st_other decorations survive. No ABI selection,
    deduplication, demangling or name-prefix rule is applied. Symbol size is
    decimal (or readelf's explicit hex); value and COMMON alignment are hex.
    This is a textual projection, not proof that ELF string bytes are lossless
    in readelf's display. Diagnostics and artifact identity belong to callers.
    """

    tables: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    saw_columns = False

    def finish() -> None:
        if current is not None:
            require(saw_columns, "readelf symbol table lacks column header")
            require(
                [row["row_index"] for row in current["rows"]] == list(range(current["row_count"])),
                "readelf symbol rows are missing, duplicated, reordered, or truncated",
            )

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        table = _SYMBOL_TABLE.fullmatch(stripped)
        if table:
            finish()
            current = {
                "table_index": len(tables), "name": table.group("name"),
                "row_count": int(table.group("count")), "rows": [],
            }
            tables.append(current)
            saw_columns = False
            continue
        require(current is not None, f"readelf symbol output precedes a table: {line}")
        if stripped.split() == _SYMBOL_COLUMNS:
            require(not saw_columns and not current["rows"], "duplicate or misplaced symbol column header")
            saw_columns = True
            continue
        require(saw_columns, "readelf symbol table lacks column header")
        match = _COMPLETE_SYMBOL_LINE.fullmatch(line)
        require(match is not None, f"malformed complete symbol row: {line}")
        raw_name = match.group("name")
        version_index = None
        if raw_name is not None:
            decoration = re.search(r" \(([0-9]+)\)$", raw_name)
            if decoration is not None and "@" in raw_name[:decoration.start()]:
                version_index = int(decoration.group(1))
                raw_name = raw_name[:decoration.start()]
                require(version_index > 0, "readelf version index must be positive")
            name, version, version_default = _split_version(raw_name)
            require("@" not in name and (version is None or "@" not in version),
                    f"invalid symbol version: {raw_name}")
        else:
            name, version, version_default = None, None, False
        size = match.group("size")
        section = match.group("section")
        current["rows"].append({
            "row_index": int(match.group("number")), "raw": line,
            "raw_name": raw_name, "name": name,
            "type": match.group("symbol_type"), "binding": match.group("binding"),
            "visibility": match.group("visibility"), "other": match.group("other"),
            "version": version, "version_default": version_default,
            "version_index": version_index, "value": match.group("value"),
            "size": size, "size_bytes": int(size, 16 if size.startswith("0x") else 10),
            "section_index": section,
            "common_alignment": int(match.group("value"), 16) if section == "COM" else None,
        })
    finish()
    require(bool(tables), "readelf output has no symbol table")
    return tables


def parse_dynamic_symbol_rows(raw: str) -> list[dict[str, Any]]:
    """Retain every dynsym row; parse_dynamic_symbols remains the v1 public view."""

    tables = parse_elf_symbol_tables(raw)
    require(len(tables) == 1 and tables[0]["name"] == ".dynsym", "expected exactly one .dynsym table")
    return tables[0]["rows"]


def parse_elf_sections(raw: str) -> dict[str, Any]:
    """Project complete ELF64 GNU readelf --wide --section-headers output.

    Section indexes define placement domains even when names repeat. Alignment
    is sh_addralign, not an inferred symbol alignment. Hex quantities remain
    raw strings; indexes, link/info and alignment are decimal integers.
    """

    count: int | None = None
    offset: str | None = None
    saw_title = False
    saw_columns = False
    saw_legend = False
    legend: list[str] = []
    sections: list[dict[str, Any]] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        declaration = _SECTION_COUNT.fullmatch(stripped)
        if declaration:
            require(count is None and not saw_title, "duplicate or misplaced section count")
            count, offset = int(declaration.group("count")), declaration.group("offset")
        elif stripped == "Section Headers:":
            require(count is not None and not saw_title, "duplicate or misplaced section title")
            saw_title = True
        elif stripped.split() == "[Nr] Name Type Address Off Size ES Flg Lk Inf Al".split():
            require(saw_title and not saw_columns, "duplicate or misplaced section columns")
            saw_columns = True
        elif stripped == "Key to Flags:":
            require(saw_columns and not saw_legend, "duplicate or misplaced section flag legend")
            saw_legend = True
        elif saw_legend:
            # Preserve the display legend but do not let an appended row become
            # invisible once the table has allegedly ended.
            require(not stripped.startswith("[") and "(" in stripped and ")" in stripped,
                    f"unrecognized section flag legend: {line}")
            legend.append(line)
        else:
            require(saw_columns, f"readelf section output precedes its columns: {line}")
            match = _SECTION_LINE.fullmatch(line)
            require(match is not None, f"malformed section row: {line}")
            record: dict[str, Any] = {"raw": line}
            for field in ("index", "link", "info", "alignment"):
                record[field] = int(match.group(field))
            for field in ("type", "address", "offset", "size", "entry_size"):
                record[field] = match.group(field)
            record["name"] = match.group("name") or ""
            record["flags"] = match.group("flags") or ""
            sections.append(record)
    require(count is not None and saw_columns and saw_legend, "incomplete section header output")
    require(len(legend) == 4
            and tuple(line.strip() for line in legend[:3]) == _PINNED_SECTION_FLAG_LEGEND_PREFIX
            and legend[3].strip() in _PINNED_SECTION_FLAG_LEGEND_ENDINGS,
            "incomplete or changed pinned readelf section flag legend")
    require([row["index"] for row in sections] == list(range(count)),
            "readelf section rows are missing, duplicated, reordered, or truncated")
    return {"section_count": count, "table_offset": offset, "sections": sections, "flag_legend": legend}


def _archive_fact_blocks(raw: str, members: Sequence[str], expected_archive: str) -> list[str]:
    """Require the complete ar order, not a name-keyed approximation of it."""

    names: list[str] = []
    blocks: list[list[str]] = []
    for line in raw.splitlines():
        label = _FILE_LINE.fullmatch(line)
        if label:
            require(label.group("archive") == expected_archive, "readelf output names a different archive")
            names.append(label.group("bracket_member") or label.group("paren_member") or "")
            blocks.append([])
        elif blocks:
            blocks[-1].append(line)
        else:
            require(not line.strip(), f"unlabelled archive fact output: {line}")
    require(names == list(members), "readelf archive member order/count differs from ar roster")
    return ["\n".join(lines) for lines in blocks]


def parse_elf_header(raw: str, *, expected_type: str, description: str = "ELF facts") -> dict[str, Any]:
    """Retain all header rows, including readelf's two distinct Version fields.

    PIE selects the complete pinned readelf DYN executable description; it is
    a display contract, not another ELF type. Returned identity and raw fields
    retain actual DYN. DYN continues to require the shared-object description.
    """

    fields: list[dict[str, str]] = []
    names: Counter[str] = Counter()
    saw_header = False
    for line in raw.splitlines():
        if not line.strip():
            continue
        if line.strip() == "ELF Header:":
            require(not saw_header, f"{description} has duplicate ELF headers")
            saw_header = True
            continue
        match = _ELF_FIELD.fullmatch(line)
        require(saw_header and line.startswith("  ") and match is not None,
                f"{description} has malformed ELF header output: {line}")
        name = match.group("name")
        names[name] += 1
        require(names[name] <= (2 if name == "Version" else 1),
                f"{description} has a duplicate ELF header field: {name}")
        fields.append({"name": name, "value": match.group("value"), "raw": line})
    require(tuple(field["name"] for field in fields) == _PINNED_ELF_HEADER_FIELDS,
            f"{description} has incomplete or changed pinned readelf ELF header fields")
    identity = _readelf_header(raw, description)
    descriptions = {"REL": "REL (Relocatable file)", "DYN": "DYN (Shared object file)",
                    "EXEC": "EXEC (Executable file)", "PIE": "DYN (Position-Independent Executable file)"}
    require(expected_type in descriptions, "unsupported ELF fact type contract")
    expected = descriptions[expected_type]
    require(identity["Type"] == expected, f"{description} is not {expected_type} ELF")
    return {"identity": identity, "fields": fields}


def parse_elf_facts(
    headers_raw: str, sections_raw: str, symbols_raw: str, *, expected_type: str,
) -> dict[str, Any]:
    """Join complete native ELF header, section and all symbol-table displays.

    The independent section roster establishes every symbol-table occurrence,
    including legitimate symbol-free CRT objects. This does not validate all
    ELF semantics or infer public ABI selection from any row.
    """

    header = parse_elf_header(headers_raw, expected_type=expected_type)
    section_facts = parse_elf_sections(sections_raw)
    section_rows = section_facts["sections"]
    section_count = next(field["value"] for field in header["fields"]
                         if field["name"] == "Number of section headers")
    require(section_count == str(len(section_rows)),
            "ELF header section count differs from section rows")
    table_sections = [row for row in section_rows if row["type"] in {"SYMTAB", "DYNSYM"}]
    tables = parse_elf_symbol_tables(symbols_raw) if symbols_raw.strip() else []
    require(len(tables) == len(table_sections), "ELF symbol/section table counts differ")
    for table, section in zip(tables, table_sections):
        require(table["name"] == section["name"], "ELF symbol table order/name differs from sections")
        require(int(section["entry_size"], 16) == 24, "native ELF64 symbol entry size is not 24")
        require(int(section["size"], 16) == table["row_count"] * 24, "ELF symbol table row count differs from section size")
        require(section["link"] < len(section_rows) and section_rows[section["link"]]["type"] == "STRTAB",
                "ELF symbol table lacks its string table section")
        table["section_index"] = section["index"]
        for row in table["rows"]:
            ndx = row["section_index"]
            if ndx.isdecimal():
                require(int(ndx) < len(section_rows), "ELF symbol section index is absent")
    return {"header": header, "header_raw": headers_raw, **section_facts, "symbol_tables": tables}


def parse_archive_elf_facts(
    headers_raw: str, sections_raw: str, symbols_raw: str, members: Sequence[str],
    *, expected_archive: str,
) -> list[dict[str, Any]]:
    """Join complete native REL member headers, sections and symbol tables.

    Inputs are three separate successful, diagnostic-free GNU readelf commands
    (-hW, -SW, -sW) against the same unchanged archive and its ar t roster. The
    caller must bind those command/artifact facts; this parser performs no tool
    calls or extraction. Every stream must match the entire roster in order.
    Missing/unsupported members raise instead of assigning a duplicate-name
    diagnostic to an invented occurrence. All occurrences are zero-based.

    A definition's placement domain is archive identity + member_index +
    symbol-table section_index + symbol row's section_index, never just the
    member/section name or nm value. Equal placements do not select ABI aliases.
    """

    require(bool(expected_archive) and bool(members), "archive facts require an archive and member roster")
    require(all(isinstance(member, str) and member and "\n" not in member for member in members),
            "invalid archive fact member roster")
    headers = _archive_fact_blocks(headers_raw, members, expected_archive)
    sections = _archive_fact_blocks(sections_raw, members, expected_archive)
    symbols = _archive_fact_blocks(symbols_raw, members, expected_archive)
    occurrences: Counter[str] = Counter()
    facts: list[dict[str, Any]] = []
    for index, member in enumerate(members):
        elf = parse_elf_facts(headers[index], sections[index], symbols[index], expected_type="REL")
        facts.append({
            "archive": expected_archive, "member": member, "member_index": index,
            "member_occurrence": occurrences[member], **elf,
        })
        occurrences[member] += 1
    return facts


def require_static_members_present(records: Sequence[Mapping[str, str]], members: Sequence[str]) -> None:
    missing = sorted({record["archive_member"] for record in records} - set(members))
    if missing:
        raise InventoryError(f"nm names a member missing from ar roster: {missing[0]}")


def parse_nm_no_global_symbols_diagnostics(raw: str, members: Sequence[str]) -> list[dict[str, str]]:
    """Retain only GNU nm's explicit no-global-definition diagnostics.

    `nm -g --defined-only` legitimately emits this line for archive members
    with no global definition.  The archive roster binds each admitted member;
    an arbitrary diagnostic must not become a smaller successful inventory.
    """

    available = Counter(members)
    observed: Counter[str] = Counter()
    records: list[dict[str, str]] = []
    prefix = f"{TOOL_PATHS['nm']}: "
    suffix = ": no symbols"
    for line in raw.splitlines():
        require(line.startswith(prefix) and line.endswith(suffix), f"nm emitted an unsupported diagnostic: {line}")
        member = line[len(prefix):-len(suffix)]
        require(bool(member), "nm no-symbol diagnostic has no archive member")
        require(member in available, f"nm diagnostic names a member missing from ar roster: {member}")
        observed[member] += 1
        require(
            observed[member] <= available[member],
            f"nm emits too many no-symbol diagnostics for archive member: {member}",
        )
        records.append({"member": member, "outcome": "no-global-defined-symbols"})
    return records


def parse_archive_members(raw: str) -> list[str]:
    members: list[str] = []
    for line in raw.splitlines():
        require(bool(line) and not line.isspace(), "ar emitted an empty archive-member row")
        require("/" not in line and "\\" not in line and "\x00" not in line, f"unsafe archive member name: {line!r}")
        members.append(line)
    require(bool(members), "ar produced no archive members")
    return members


def _archive_block_outcome(member: str, lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in lines:
        match = _ELF_FIELD.match(line)
        if match:
            values[match.group("name")] = match.group("value")
    error = next((line.split("Error:", 1)[1].strip() for line in lines if "Error:" in line), None)
    if error is not None:
        return {"member": member, "outcome": "unsupported", "detail": error}
    required = {
        "Class": "ELF64",
        "Data": "2's complement, little endian",
        "Machine": "Advanced Micro Devices X86-64",
    }
    if all(values.get(key) == expected for key, expected in required.items()):
        return {"member": member, "outcome": "x86_64-elf"}
    detail = "; ".join(f"{key}={values.get(key, '<absent>')}" for key in sorted(required))
    return {"member": member, "outcome": "unsupported", "detail": detail}


def parse_archive_member_headers(
    raw: str,
    members: Sequence[str],
    *,
    expected_archive: str | None = None,
) -> list[dict[str, str]]:
    """Keep one outcome per ar member; an absent block is visibly incomplete.

    GNU readelf may emit an unlabelled archive-member error on stderr.  This
    parser therefore never guesses which duplicate member caused such a
    diagnostic.  The caller records diagnostics and marks that inspection
    incomplete; only a File-labelled stdout block can identify one member.
    """

    blocks: list[tuple[str, list[str]]] = []
    current_member: str | None = None
    current_lines: list[str] = []
    for line in raw.splitlines():
        match = _FILE_LINE.match(line)
        if match:
            if expected_archive is not None:
                require(
                    match.group("archive") == expected_archive,
                    f"readelf output names a different archive: {match.group('archive')}",
                )
            if current_member is not None:
                blocks.append((current_member, current_lines))
            current_member = match.group("bracket_member") or match.group("paren_member")
            require(current_member is not None, "readelf archive member label is absent")
            current_lines = []
        elif current_member is not None:
            current_lines.append(line)
    if current_member is not None:
        blocks.append((current_member, current_lines))

    observations: list[dict[str, str]] = []
    by_member: dict[str, list[list[str]]] = defaultdict(list)
    for member, lines in blocks:
        by_member[member].append(lines)
    seen: dict[str, int] = defaultdict(int)
    for member in members:
        occurrence = seen[member]
        seen[member] += 1
        if occurrence >= len(by_member[member]):
            observations.append({"member": member, "outcome": "unobserved", "detail": "readelf emitted no member block"})
        else:
            observations.append(_archive_block_outcome(member, by_member[member][occurrence]))
    for member, blocks_for_member in by_member.items():
        if len(blocks_for_member) > seen.get(member, 0):
            for _unused in blocks_for_member[seen.get(member, 0):]:
                observations.append({"member": member, "outcome": "unexpected", "detail": "readelf emitted an extra member block"})
    return observations


def dynamic_aliases(records: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    groups: dict[tuple[object, object, object], list[dict[str, object]]] = defaultdict(list)
    for record in records:
        value = record["value"]
        if value != "0000000000000000":
            groups[(record["type"], value, record["section_index"])].append(dict(record))
    aliases: list[dict[str, object]] = []
    for (symbol_type, value, section_index), members in sorted(
        groups.items(), key=lambda item: (str(item[0][0]), str(item[0][1]), str(item[0][2]))
    ):
        if len(members) > 1:
            aliases.append({
                "type": symbol_type,
                "value": value,
                "section_index": section_index,
                "symbols": [
                    {
                        "name": item["name"],
                        "version": item["version"],
                        "version_default": item["version_default"],
                    }
                    for item in members
                ],
            })
    return aliases


def _dynamic_key(record: Mapping[str, object]) -> tuple[object, object, object]:
    return record["name"], record["version"], record["version_default"]


def _key_record(key: tuple[object, object, object]) -> dict[str, object]:
    return {"name": key[0], "version": key[1], "version_default": key[2]}


def compare_dynamic_symbols(
    reference: Sequence[Mapping[str, object]], candidate: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    reference_map = {_dynamic_key(record): dict(record) for record in reference}
    candidate_map = {_dynamic_key(record): dict(record) for record in candidate}
    require(len(reference_map) == len(reference), "reference dynamic rows duplicate a symbol identity")
    require(len(candidate_map) == len(candidate), "candidate dynamic rows duplicate a symbol identity")
    missing = [reference_map[key] for key in sorted(reference_map.keys() - candidate_map.keys(), key=repr)]
    extra = [candidate_map[key] for key in sorted(candidate_map.keys() - reference_map.keys(), key=repr)]
    compatibility_differences: list[dict[str, object]] = []
    measurement_differences: list[dict[str, object]] = []
    for key in sorted(reference_map.keys() & candidate_map.keys(), key=repr):
        left, right = reference_map[key], candidate_map[key]
        changed = {
            field: {"reference": left[field], "candidate": right[field]}
            for field in ("type", "binding", "visibility")
            if left[field] != right[field]
        }
        if changed:
            compatibility_differences.append({"key": _key_record(key), "fields": changed})
        measurement = {
            field: {"reference": left[field], "candidate": right[field]}
            for field in ("value", "section_index")
            if left[field] != right[field]
        }
        if left["type"] not in {"OBJECT", "TLS"} and right["type"] not in {"OBJECT", "TLS"} and left["size"] != right["size"]:
            measurement["size"] = {"reference": left["size"], "candidate": right["size"]}
        if measurement:
            measurement_differences.append({
                "key": _key_record(key),
                "reference": {field: left[field] for field in ("size", "value", "section_index")},
                "candidate": {field: right[field] for field in ("size", "value", "section_index")},
            })
    versions: dict[object, dict[str, list[tuple[object, object]]]] = defaultdict(lambda: {"reference": [], "candidate": []})
    for record in reference:
        versions[record["name"]]["reference"].append((record["version"], record["version_default"]))
    for record in candidate:
        versions[record["name"]]["candidate"].append((record["version"], record["version_default"]))
    common_names = {
        record["name"]
        for record in reference
    } & {
        record["name"]
        for record in candidate
    }
    version_differences = [
        {
            "name": name,
            "reference": [[version, default] for version, default in sorted(value["reference"], key=repr)],
            "candidate": [[version, default] for version, default in sorted(value["candidate"], key=repr)],
        }
        for name, value in sorted(versions.items(), key=lambda item: str(item[0]))
        if name in common_names
        and sorted(value["reference"], key=repr) != sorted(value["candidate"], key=repr)
    ]
    data_size_differences = [
        {
            "key": _key_record(key),
            "type": reference_map[key]["type"],
            "reference_size": reference_map[key]["size"],
            "candidate_size": candidate_map[key]["size"],
        }
        for key in sorted(reference_map.keys() & candidate_map.keys(), key=repr)
        if reference_map[key]["type"] == candidate_map[key]["type"]
        and reference_map[key]["type"] in {"OBJECT", "TLS"}
        and reference_map[key]["size"] != candidate_map[key]["size"]
    ]
    return {
        "missing": missing,
        "extra": extra,
        "compatibility_differences": compatibility_differences,
        "version_differences": version_differences,
        "measurement_differences": measurement_differences,
        "data_size_differences": data_size_differences,
    }


def compare_static_symbols(
    reference: Sequence[Mapping[str, str]], candidate: Sequence[Mapping[str, str]]
) -> dict[str, object]:
    """Triage counts by raw name/class while retaining full member rows elsewhere."""

    reference_counts = Counter((record["name"], record["nm_type"]) for record in reference)
    candidate_counts = Counter((record["name"], record["nm_type"]) for record in candidate)
    missing = [
        {"name": name, "nm_type": nm_type, "count": count - candidate_counts[(name, nm_type)]}
        for (name, nm_type), count in sorted(reference_counts.items())
        if count > candidate_counts[(name, nm_type)]
    ]
    extra = [
        {"name": name, "nm_type": nm_type, "count": count - reference_counts[(name, nm_type)]}
        for (name, nm_type), count in sorted(candidate_counts.items())
        if count > reference_counts[(name, nm_type)]
    ]
    reference_classes: dict[str, list[str]] = defaultdict(list)
    candidate_classes: dict[str, list[str]] = defaultdict(list)
    for name, nm_type in reference_counts:
        reference_classes[name].append(nm_type)
    for name, nm_type in candidate_counts:
        candidate_classes[name].append(nm_type)
    class_differences = [
        {
            "name": name,
            "reference": sorted(reference_classes[name]),
            "candidate": sorted(candidate_classes[name]),
        }
        for name in sorted(set(reference_classes) & set(candidate_classes))
        if sorted(reference_classes[name]) != sorted(candidate_classes[name])
    ]
    return {"missing": missing, "extra": extra, "class_differences": class_differences}


def _relative_path(value: object, description: str) -> str:
    require(isinstance(value, str) and value, f"{description} has no path")
    candidate = Path(value)
    require(
        not candidate.is_absolute()
        and bool(candidate.parts)
        and all(part not in {"", ".", ".."} for part in candidate.parts),
        f"{description} has an unsafe relative path",
    )
    return candidate.as_posix()


def _recorded_relative_file(root: Path, value: object, description: str) -> Path:
    relative = _relative_path(value, description)
    return physical_regular(root / relative, description)


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.write_bytes(data)
        path.chmod(0o600)
    except OSError as error:
        raise InventoryError(f"cannot retain evidence: {path}") from error


def _snapshot_regular(output_root: Path, source: Path, relative: str, logical_path: str) -> dict[str, object]:
    source = physical_regular(source, f"snapshot source {logical_path}")
    destination = output_root / _relative_path(relative, "retained snapshot")
    require(not destination.exists(), f"duplicate retained snapshot: {relative}")
    before = file_record(source, logical_path=logical_path)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(source, destination)
        destination.chmod(0o600)
    except OSError as error:
        raise InventoryError(f"cannot retain input snapshot: {source}") from error
    after = file_record(source, logical_path=logical_path)
    require(before == after, f"snapshot source changed during capture: {logical_path}")
    retained = file_record(destination, logical_path=relative)
    require(
        retained["sha256"] == before["sha256"] and retained["size"] == before["size"],
        f"retained snapshot differs from source: {logical_path}",
    )
    return {
        "original": before,
        "retained": retained,
    }


def _validate_snapshot(
    output_root: Path,
    record: object,
    description: str,
    *,
    expected_original_path: str | None = None,
    expected_retained_path: str | None = None,
) -> None:
    record = require_exact_keys(record, {"original", "retained"}, description)
    original = require_exact_keys(record["original"], {"path", "sha256", "size", "mode"}, f"{description} original")
    retained = require_exact_keys(record["retained"], {"path", "sha256", "size", "mode"}, f"{description} retained")
    relative = _relative_path(retained["path"], f"{description} retained")
    if expected_original_path is not None:
        require(original["path"] == expected_original_path, f"{description} original path drifted")
    else:
        require(isinstance(original["path"], str) and original["path"].startswith("/"), f"{description} original path is not absolute")
    if expected_retained_path is not None:
        require(relative == expected_retained_path, f"{description} retained path drifted")
    require(relative.startswith(INPUT_DIRECTORY + "/") or relative.startswith(RAW_DIRECTORY + "/"), f"{description} retained path is outside report evidence")
    path = _recorded_relative_file(output_root, relative, f"{description} retained")
    observed = file_record(path, logical_path=relative)
    require(observed == retained, f"{description} retained bytes or mode changed")
    require(
        isinstance(original["sha256"], str) and _SHA256.fullmatch(original["sha256"]) is not None
        and type(original["size"]) is int and original["size"] >= 0
        and type(original["mode"]) is int,
        f"{description} original identity is malformed",
    )
    require(
        retained["sha256"] == original["sha256"] and retained["size"] == original["size"],
        f"{description} retained source identity differs",
    )


def _write_raw(output_root: Path, name: str, value: str) -> dict[str, object]:
    relative = f"{RAW_DIRECTORY}/{name}"
    destination = output_root / relative
    _write_private(destination, value.encode("utf-8"))
    return file_record(destination, logical_path=relative)


def _read_raw(output_root: Path, record: object, description: str) -> str:
    record = require_exact_keys(record, {"path", "sha256", "size", "mode"}, description)
    relative = _relative_path(record["path"], description)
    require(relative.startswith(RAW_DIRECTORY + "/"), f"{description} is not a raw evidence path")
    path = _recorded_relative_file(output_root, relative, description)
    observed = file_record(path, logical_path=relative)
    require(observed == record, f"{description} bytes or mode changed")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise InventoryError(f"{description} is not UTF-8") from error


def _readelf_header(raw: str, description: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    saw_header = False
    for line in raw.splitlines():
        if line.strip() == "ELF Header:":
            saw_header = True
            continue
        if saw_header:
            match = _ELF_FIELD.match(line)
            if match:
                fields[match.group("name")] = match.group("value")
    require(saw_header, f"{description} has no ELF header")
    require(fields.get("Class") == "ELF64", f"{description} is not ELF64")
    require(fields.get("Data") == "2's complement, little endian", f"{description} is not little-endian")
    require(fields.get("Machine") == "Advanced Micro Devices X86-64", f"{description} is not x86-64")
    require("Type" in fields, f"{description} lacks ELF type")
    return {
        field: fields[field]
        for field in ("Class", "Data", "OS/ABI", "ABI Version", "Type", "Machine", "Entry point address")
        if field in fields
    }


def _readelf_program(raw: str) -> dict[str, object]:
    declared_count: int | None = None
    entries: list[dict[str, str]] = []
    unparsed_rows: list[str] = []
    interpreter: str | None = None
    in_table = False
    for line in raw.splitlines():
        count = _PROGRAM_COUNT.match(line)
        if count:
            require(declared_count is None, "readelf program output declares multiple header counts")
            declared_count = int(count.group("count"))
        if line.strip() == "Program Headers:":
            in_table = True
            continue
        if line.strip() == "Section to Segment mapping:":
            in_table = False
            continue
        match = re.search(r"\[Requesting program interpreter: (?P<path>[^\]]+)\]", line)
        if match:
            require(interpreter is None, "readelf program output has multiple interpreters")
            interpreter = match.group("path")
            continue
        if not in_table or not line.strip():
            continue
        fields = line.split()
        if fields and fields[0] in {"Type", "FileSiz"}:
            continue
        if len(fields) >= 2 and fields[1].startswith("0x"):
            entries.append({"type": fields[0], "raw": line})
        else:
            unparsed_rows.append(line)
    return {
        "declared_count": declared_count,
        "entries": entries,
        "unparsed_rows": unparsed_rows,
        "interpreter": interpreter,
        "complete": (
            declared_count is not None
            and len(entries) == declared_count
            and not unparsed_rows
        ),
    }


def _readelf_dynamic(raw: str) -> list[dict[str, str]]:
    declared_count: int | None = None
    tags: list[dict[str, str]] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        section = _DYNAMIC_SECTION.match(stripped)
        if section:
            require(declared_count is None, "readelf dynamic output declares multiple dynamic sections")
            declared_count = int(section.group("count"))
            continue
        require(declared_count is not None, f"unrecognized dynamic output before section header: {line}")
        if _DYNAMIC_TABLE_HEADER.match(stripped):
            continue
        match = _DYNAMIC_TAG.match(line)
        if match:
            tags.append({"tag": match.group("tag"), "value": match.group("value")})
            continue
        raise InventoryError(f"unrecognized dynamic tag row: {line}")
    require(declared_count is not None, "readelf dynamic output has no dynamic section")
    require(
        len(tags) == declared_count,
        "readelf dynamic-tag rows are missing, duplicated, or truncated",
    )
    return tags


def _readelf_relocations(raw: str) -> dict[str, object]:
    sections: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    no_relocations = False
    for line in raw.splitlines():
        stripped = line.strip()
        section = _RELOCATION_SECTION.match(stripped)
        if section:
            current = {
                "name": section.group("name"),
                "declared_entries": int(section.group("count")),
                "raw_entries": [],
                "unclassified_rows": [],
            }
            sections.append(current)
            continue
        if stripped == "There are no relocations in this file.":
            require(not sections and current is None, "readelf relocation output mixes empty and populated tables")
            no_relocations = True
            continue
        if current is None or not stripped:
            continue
        if stripped.startswith(("Offset", "000000", "Info", "Type", "Symbol's")):
            # The table header and conventional relocation rows are handled
            # below; only rows with a relocation class count as parsed.
            pass
        types = _RELOCATION_TYPE.findall(stripped)
        if types:
            raw_entries = current["raw_entries"]
            require(isinstance(raw_entries, list), "relocation raw entry state drifted")
            raw_entries.append({"raw": line, "types": types})
        elif stripped.startswith(("Offset", "Info", "Type", "Symbol's")):
            continue
        else:
            unclassified = current["unclassified_rows"]
            require(isinstance(unclassified, list), "relocation unclassified state drifted")
            unclassified.append(line)
    counts = Counter(_RELOCATION_TYPE.findall(raw))
    summaries: list[dict[str, object]] = []
    for section in sections:
        raw_entries = section["raw_entries"]
        unclassified = section["unclassified_rows"]
        require(isinstance(raw_entries, list) and isinstance(unclassified, list), "relocation section state drifted")
        summaries.append({
            "name": section["name"],
            "declared_entries": section["declared_entries"],
            "parsed_rows": len(raw_entries),
            "unclassified_rows": unclassified,
            "complete": not unclassified and (
                str(section["name"]).startswith(".relr")
                or len(raw_entries) == int(section["declared_entries"])
            ),
        })
    return {
        "no_relocations": no_relocations,
        "sections": summaries,
        "classes": [{"type": kind, "count": counts[kind]} for kind in sorted(counts)],
        "complete": all(section["complete"] for section in summaries) and not (no_relocations and summaries),
    }


def _stable_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _git(*arguments: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", "-c", f"safe.directory={ROOT}", *arguments],
            cwd=ROOT,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise InventoryError("cannot read collector Git identity") from error


def collector_source_seal() -> dict[str, object]:
    """Seal the exact clean checkout which executed this collector."""

    require(
        not _git("status", "--porcelain", "--untracked-files=all").strip(),
        "native ABI inventory collection requires a clean collector checkout",
    )
    revision = _git("rev-parse", "HEAD").decode("ascii").strip()
    require(_REVISION.fullmatch(revision) is not None, "collector Git revision is invalid")
    names = sorted(name for name in _git("ls-files", "-z", "--cached").split(b"\0") if name)
    digest = hashlib.sha256()
    for name in names:
        path = ROOT / os.fsdecode(name)
        try:
            mode = path.lstat().st_mode
            payload = os.fsencode(os.readlink(path)) if stat.S_ISLNK(mode) else path.read_bytes()
        except OSError as error:
            raise InventoryError(f"cannot seal collector source: {path}") from error
        digest.update(name + b"\0" + str(stat.S_IMODE(mode)).encode("ascii") + b"\0")
        digest.update(hashlib.sha256(payload).digest())
    return {
        "revision": revision,
        "content_sha256": digest.hexdigest(),
        "clean": True,
    }


def _validate_collector_source_seal(record: object) -> None:
    record = require_exact_keys(record, {"revision", "content_sha256", "clean"}, "collector execution source")
    require(record["clean"] is True, "collector execution source is not clean")
    require(isinstance(record["revision"], str) and _REVISION.fullmatch(record["revision"]) is not None, "collector execution revision malformed")
    require(
        isinstance(record["content_sha256"], str) and _SHA256.fullmatch(record["content_sha256"]) is not None,
        "collector execution content digest malformed",
    )
    require(record == collector_source_seal(), "current collector Git revision or content differs")


def _tool_records(output_root: Path) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for name, source in TOOL_PATHS.items():
        source = physical_executable(source, f"{name} tool")
        # Running a tool without operands is deliberately not an identity probe;
        # bytes are copied and every collection command below names this exact
        # physical executable and a C locale.
        records[name] = _snapshot_regular(
            output_root,
            source,
            f"{TOOLS_COPY_ROOT}/{name}",
            str(source),
        )
    return records


def _run_tool(
    output_root: Path,
    *,
    key: str,
    tool_name: str,
    arguments: Sequence[str],
    artifact: str,
    tool_record: Mapping[str, object],
    allow_diagnostics: bool = False,
    allow_nonzero: bool = False,
) -> dict[str, object]:
    tool = physical_executable(TOOL_PATHS[tool_name], f"{tool_name} tool")
    argv = [str(tool), *arguments]
    try:
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=TOOL_ENVIRONMENT,
            check=False,
            timeout=TOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise InventoryError(f"{tool_name} exceeded the {TOOL_TIMEOUT_SECONDS}s inspection deadline: {artifact}") from error
    except OSError as error:
        raise InventoryError(f"cannot execute {tool_name}: {tool}") from error
    require(
        allow_nonzero or result.returncode == 0,
        f"{tool_name} failed for {artifact} with exit status {result.returncode}: {result.stderr.strip()}",
    )
    if not allow_diagnostics:
        require_empty_diagnostics(tool_name, result.stderr)
    return {
        "key": key,
        "tool": tool_name,
        "tool_identity": tool_record,
        "argv": argv,
        "artifact": artifact,
        "artifact_identity": file_record(Path(arguments[-1]), logical_path=artifact),
        "environment": dict(TOOL_ENVIRONMENT),
        "returncode": result.returncode,
        "stdout": _write_raw(output_root, f"{key}.stdout", result.stdout),
        "stderr": _write_raw(output_root, f"{key}.stderr", result.stderr),
        "diagnostics_allowed": allow_diagnostics,
    }


def _validate_command(
    output_root: Path,
    record: object,
    *,
    key: str,
    tool_name: str,
    arguments: Sequence[str],
    artifact: str,
    artifact_identity: Mapping[str, object],
    tool_record: Mapping[str, object],
    diagnostics_allowed: bool,
) -> tuple[str, str]:
    record = require_exact_keys(
        record,
        {
            "key", "tool", "tool_identity", "argv", "artifact", "artifact_identity", "environment",
            "returncode", "stdout", "stderr", "diagnostics_allowed",
        },
        f"command {key}",
    )
    tool = TOOL_PATHS[tool_name]
    require(record["key"] == key and record["tool"] == tool_name, f"command {key} identity drifted")
    require(record["tool_identity"] == tool_record, f"command {key} tool identity drifted")
    require(record["argv"] == [str(tool), *arguments], f"command {key} argv drifted")
    require(record["artifact"] == artifact, f"command {key} artifact selection drifted")
    require(record["artifact_identity"] == artifact_identity, f"command {key} artifact identity drifted")
    require(record["environment"] == TOOL_ENVIRONMENT, f"command {key} locale boundary drifted")
    require(type(record["returncode"]) is int and record["returncode"] >= 0, f"command {key} return code malformed")
    require(record["diagnostics_allowed"] is diagnostics_allowed, f"command {key} diagnostic policy drifted")
    stdout = _read_raw(output_root, record["stdout"], f"command {key} stdout")
    stderr = _read_raw(output_root, record["stderr"], f"command {key} stderr")
    if not diagnostics_allowed:
        require(record["returncode"] == 0, f"command {key} did not finish successfully")
        require_empty_diagnostics(tool_name, stderr)
    return stdout, stderr


def _logical_child(root: str, relative: str) -> str:
    return root.rstrip("/") + "/" + _relative_path(relative, "logical product path")


def _product_record(root: Path, *, logical_root: str, kind: str) -> dict[str, object]:
    root = physical_directory(root, f"{kind} product")
    try:
        if kind == "static":
            manifest_path, payload_files = product_evidence._validate_static_product(root)
        elif kind == "dynamic":
            manifest_path, payload_files = product_evidence._validate_dynamic_product(root)
        else:
            raise InventoryError(f"unknown product kind: {kind}")
    except product_evidence.ProductEvidenceError as error:
        raise InventoryError(f"{kind} product does not validate: {error}") from error
    if kind == "static":
        selection = {
            "libc_archive": file_record(
                root / "usr/lib/libc.a",
                logical_path=_logical_child(logical_root, "usr/lib/libc.a"),
            ),
            "archive_aliases": {
                "status": "unclassified",
                "reason": (
                    "nm rows lack member occurrence plus section identity; equal "
                    "raw values do not establish static aliases"
                ),
            },
        }
    else:
        alias = root / "lib/ld-musl-x86_64.so.1"
        try:
            mode = alias.lstat().st_mode
            target = os.readlink(alias)
        except OSError as error:
            raise InventoryError("dynamic product loader alias is unreadable") from error
        require(stat.S_ISLNK(mode), "dynamic product loader alias is not a symlink")
        require(target == "ld-crabc-x86_64.so.1", "dynamic product loader alias target drifted")
        selection = {
            "libc_shared": file_record(
                root / "usr/lib/libc.so",
                logical_path=_logical_child(logical_root, "usr/lib/libc.so"),
            ),
            "loader": file_record(
                root / "lib/ld-crabc-x86_64.so.1",
                logical_path=_logical_child(logical_root, "lib/ld-crabc-x86_64.so.1"),
            ),
            "loader_alias": {
                "path": _logical_child(logical_root, "lib/ld-musl-x86_64.so.1"),
                "target": target,
            },
        }
    result: dict[str, object] = {
        "kind": kind,
        "root": logical_root,
        "manifest": file_record(
            manifest_path,
            logical_path=_logical_child(logical_root, "share/crabc/manifest.json"),
        ),
        "payload_files": {name: payload_files[name] for name in sorted(payload_files)},
        "selection": selection,
    }
    if kind == "dynamic":
        manifest = result["manifest"]
        payloads = result["payload_files"]
        require(isinstance(manifest, dict) and isinstance(payloads, dict), "dynamic product record state drifted")
        result["materialization_state"] = _materialized_dynamic_state(
            root,
            logical_root,
            manifest_identity=manifest,
            payload_files=payloads,
        )
    return result


DYNAMIC_STATE_RELATIVE = "share/crabc/dynamic-product-state.json"
DYNAMIC_STATE_LOGICAL_PATH = _logical_child(str(DYNAMIC_PRODUCT_PATH), DYNAMIC_STATE_RELATIVE)


def _require_static_preparation_file(
    receipt: Path,
    output_root: Path,
) -> dict[str, object]:
    receipt = physical_regular(receipt, "static preparation receipt")
    snapshot = _snapshot_regular(
        output_root,
        receipt,
        f"{RECEIPTS_COPY_ROOT}/static-preparation.json",
        str(STATIC_PREPARATION_PATH),
    )
    return {
        "logical_path": str(STATIC_PREPARATION_PATH),
        "identity": file_record(receipt, logical_path=str(STATIC_PREPARATION_PATH)),
        "snapshot": snapshot,
    }


def _validate_static_preparation_file(output_root: Path, record: object) -> dict[str, Any]:
    record = require_exact_keys(record, {"logical_path", "identity", "snapshot"}, "static preparation receipt")
    require(record["logical_path"] == str(STATIC_PREPARATION_PATH), "static preparation logical path drifted")
    identity = require_exact_keys(record["identity"], {"path", "sha256", "size", "mode"}, "static preparation identity")
    require(identity["path"] == str(STATIC_PREPARATION_PATH), "static preparation identity path drifted")
    _validate_snapshot(
        output_root,
        record["snapshot"],
        "static preparation receipt snapshot",
        expected_original_path=str(STATIC_PREPARATION_PATH),
        expected_retained_path=f"{RECEIPTS_COPY_ROOT}/static-preparation.json",
    )
    snapshot = require_exact_keys(record["snapshot"], {"original", "retained"}, "static preparation receipt snapshot")
    require(snapshot["original"] == identity, "static preparation snapshot identity drifted")
    retained = require_exact_keys(snapshot["retained"], {"path", "sha256", "size", "mode"}, "static preparation retained")
    return read_json(
        _recorded_relative_file(output_root, retained["path"], "static preparation retained"),
        "retained static preparation receipt",
    )


def _materialization_state_shape(state: object) -> dict[str, Any]:
    state = require_exact_keys(
        state,
        {
            "schema", "status", "source_sha256", "contracts", "payload_files",
            "runtime_v1_published", "campaign_complete", "public_support", "modes",
            "runtime_profile", "qualification",
        },
        "dynamic materialization state",
    )
    require(
        state["schema"] == "crabc.x86_64-owned-dynamic-materialization/v1",
        "dynamic materialization state schema drifted",
    )
    require(state["status"] == "materialized-unqualified", "dynamic materialization state is not unqualified")
    require(
        isinstance(state["source_sha256"], str) and _SHA256.fullmatch(state["source_sha256"]) is not None,
        "dynamic materialization source digest is invalid",
    )
    contracts = state["contracts"]
    require(isinstance(contracts, dict) and set(contracts) == set(dynamic_materialization.CONTRACTS), "dynamic materialization contract roster drifted")
    for name, digest in contracts.items():
        require(isinstance(digest, str) and _SHA256.fullmatch(digest) is not None, f"dynamic materialization contract digest is invalid: {name}")
    payload_files = state["payload_files"]
    require(isinstance(payload_files, dict) and payload_files, "dynamic materialization payload roster is absent")
    for name, digest in payload_files.items():
        relative = _relative_path(name, "dynamic materialization payload")
        require(isinstance(digest, str) and _SHA256.fullmatch(digest) is not None, f"dynamic materialization payload digest is invalid: {relative}")
    require(
        state["runtime_v1_published"] is False
        and state["campaign_complete"] is False
        and state["public_support"] is False,
        "dynamic materialization state makes a qualification or promotion claim",
    )
    require(
        state["modes"] == ["dynamic-pie", "dynamic-non-pie", "dynamic-shared-object"],
        "dynamic materialization mode roster drifted",
    )
    require(
        state["runtime_profile"] == dynamic_materialization.MATERIALIZATION_PROFILE
        and state["qualification"] == dynamic_materialization.MATERIALIZATION_QUALIFICATION,
        "dynamic materialization boundary drifted",
    )
    return state


def _materialized_dynamic_state(
    root: Path,
    logical_root: str,
    *,
    manifest_identity: Mapping[str, object],
    payload_files: Mapping[str, str],
) -> dict[str, object]:
    """Validate the selected product's canonical, unqualified state file.

    The file is selected only through the manifest-bound product root.  Its
    source and contract checks reuse the current materialization owner; no
    dynamic qualification receipt is an input to this inventory.
    """

    state_path = physical_regular(root / DYNAMIC_STATE_RELATIVE, "dynamic materialization state")
    state = _materialization_state_shape(read_json(state_path, "dynamic materialization state"))
    try:
        expected_contracts = dynamic_materialization.contract_digests()
    except (OSError, ValueError, RuntimeError) as error:
        raise InventoryError(f"current dynamic materialization contracts do not validate: {error}") from error
    require(
        state["contracts"] == expected_contracts,
        "dynamic materialization contracts differ from the current contract",
    )
    expected_payload_files = {
        name: digest
        for name, digest in payload_files.items()
        if name != DYNAMIC_STATE_RELATIVE
    }
    require(
        state["payload_files"] == expected_payload_files,
        "dynamic materialization state does not bind the selected payload roster",
    )
    require(
        manifest_identity["sha256"] == sha256(root / "share/crabc/manifest.json"),
        "dynamic materialization manifest identity drifted",
    )
    return {
        "logical_path": _logical_child(logical_root, DYNAMIC_STATE_RELATIVE),
        "identity": file_record(
            state_path,
            logical_path=_logical_child(logical_root, DYNAMIC_STATE_RELATIVE),
        ),
        "manifest_sha256": manifest_identity["sha256"],
        "state": state,
    }


def _snapshot_dynamic_materialization_state(
    output_root: Path,
    dynamic_product: Path,
) -> dict[str, object]:
    state_path = physical_regular(dynamic_product / DYNAMIC_STATE_RELATIVE, "dynamic materialization state")
    snapshot = _snapshot_regular(
        output_root,
        state_path,
        f"{RECEIPTS_COPY_ROOT}/dynamic-product-state.json",
        DYNAMIC_STATE_LOGICAL_PATH,
    )
    return {
        "logical_path": DYNAMIC_STATE_LOGICAL_PATH,
        "identity": file_record(state_path, logical_path=DYNAMIC_STATE_LOGICAL_PATH),
        "snapshot": snapshot,
    }


def _validate_dynamic_materialization_state_file(
    output_root: Path,
    record: object,
) -> dict[str, Any]:
    record = require_exact_keys(record, {"logical_path", "identity", "snapshot"}, "dynamic materialization state file")
    require(record["logical_path"] == DYNAMIC_STATE_LOGICAL_PATH, "dynamic materialization state path drifted")
    identity = require_exact_keys(record["identity"], {"path", "sha256", "size", "mode"}, "dynamic materialization state identity")
    require(identity["path"] == DYNAMIC_STATE_LOGICAL_PATH, "dynamic materialization state identity path drifted")
    _validate_snapshot(
        output_root,
        record["snapshot"],
        "dynamic materialization state snapshot",
        expected_original_path=DYNAMIC_STATE_LOGICAL_PATH,
        expected_retained_path=f"{RECEIPTS_COPY_ROOT}/dynamic-product-state.json",
    )
    snapshot = require_exact_keys(record["snapshot"], {"original", "retained"}, "dynamic materialization state snapshot")
    require(snapshot["original"] == identity, "dynamic materialization snapshot identity drifted")
    retained = require_exact_keys(snapshot["retained"], {"path", "sha256", "size", "mode"}, "dynamic materialization retained")
    return _materialization_state_shape(
        read_json(
            _recorded_relative_file(output_root, retained["path"], "dynamic materialization retained"),
            "retained dynamic materialization state",
        )
    )


def _bind_product_provenance(
    *,
    static_receipt: Path,
    dynamic_product_root: Path,
    static_product: Mapping[str, object],
    dynamic_product: Mapping[str, object],
    output_root: Path | None = None,
) -> dict[str, object]:
    """Cross-bind prepared static provenance to one materialized dynamic product.

    Static preparation supplies the original clean revision.  The selected
    dynamic product supplies its manifest-bound state file and explicitly stays
    materialized/unqualified.  A complete dynamic qualification receipt is not
    required merely to inspect ELF and symbol inventories.
    """

    static = read_json(static_receipt, "static preparation receipt")
    require(
        static.get("schema") == "crabc.x86_64-owned-posix-static-preparation/v1",
        "static preparation receipt schema drifted",
    )
    require(
        static.get("status") == "prepared-unqualified",
        "static preparation receipt is not prepared-unqualified",
    )
    source = require_exact_keys(static.get("source"), {"content_sha256", "revision"}, "static preparation source")
    require(
        isinstance(source["content_sha256"], str) and _SHA256.fullmatch(source["content_sha256"]) is not None,
        "static preparation source content hash is invalid",
    )
    require(
        isinstance(source["revision"], str) and _REVISION.fullmatch(source["revision"]) is not None,
        "static preparation source revision is invalid",
    )
    products = static.get("products")
    require(isinstance(products, dict), "static preparation receipt has no products")
    primary = products.get("primary")
    require(isinstance(primary, dict), "static preparation receipt has no primary product")
    static_manifest = primary.get("manifest")
    require(isinstance(static_manifest, dict), "static preparation primary manifest is absent")
    require_digest(static_manifest.get("sha256"), str(static_product["manifest"]["sha256"]), "static preparation manifest")

    materialization = dynamic_product.get("materialization_state")
    require(isinstance(materialization, dict), "dynamic product materialization state is absent")
    materialization = require_exact_keys(
        materialization,
        {"logical_path", "identity", "manifest_sha256", "state"},
        "dynamic product materialization state",
    )
    require(materialization["logical_path"] == DYNAMIC_STATE_LOGICAL_PATH, "dynamic materialization state path drifted")
    state = _materialization_state_shape(materialization["state"])
    require(
        state["source_sha256"] == source["content_sha256"],
        "static preparation and dynamic materialization bind different source content",
    )
    require(
        materialization["manifest_sha256"] == dynamic_product["manifest"]["sha256"],
        "dynamic materialization state does not bind the selected manifest",
    )
    require(
        materialization["identity"]["sha256"] == dynamic_product["payload_files"][DYNAMIC_STATE_RELATIVE],
        "dynamic materialization state does not bind the selected payload",
    )

    record: dict[str, object] = {
        "candidate_build": {
            "classification": "materialized-unqualified-product-measurement-only",
            "revision": source["revision"],
            "source_content_sha256": source["content_sha256"],
            "revision_provenance": (
                "static preparation source.revision, cross-bound to the selected "
                "dynamic product state source_sha256; no dynamic qualification is claimed"
            ),
        },
        "static_preparation": {
            "logical_path": str(STATIC_PREPARATION_PATH),
            "source": dict(source),
            "product_selector": "primary",
            "manifest_sha256": static_manifest["sha256"],
        },
        "dynamic_materialization": {
            "logical_path": DYNAMIC_STATE_LOGICAL_PATH,
            "identity": materialization["identity"],
            "manifest_sha256": materialization["manifest_sha256"],
            "state": state,
        },
    }
    if output_root is not None:
        record["static_preparation"]["receipt"] = _require_static_preparation_file(static_receipt, output_root)
        record["dynamic_materialization"]["state_file"] = _snapshot_dynamic_materialization_state(
            output_root,
            dynamic_product_root,
        )
    return record


def _validate_product_provenance(
    output_root: Path,
    record: object,
    *,
    static_receipt: Path,
    dynamic_product_root: Path,
    static_product: Mapping[str, object],
    dynamic_product: Mapping[str, object],
) -> None:
    record = require_exact_keys(
        record,
        {"candidate_build", "static_preparation", "dynamic_materialization"},
        "materialized product provenance",
    )
    candidate_build = require_exact_keys(
        record["candidate_build"],
        {"classification", "revision", "source_content_sha256", "revision_provenance"},
        "candidate build identity",
    )
    require(
        candidate_build["classification"] == "materialized-unqualified-product-measurement-only",
        "candidate build classification drifted",
    )
    require(isinstance(candidate_build["revision"], str) and _REVISION.fullmatch(candidate_build["revision"]) is not None, "candidate build revision drifted")
    require(
        isinstance(candidate_build["source_content_sha256"], str)
        and _SHA256.fullmatch(candidate_build["source_content_sha256"]) is not None,
        "candidate build source digest drifted",
    )
    require(
        candidate_build["revision_provenance"]
        == "static preparation source.revision, cross-bound to the selected dynamic product state source_sha256; no dynamic qualification is claimed",
        "candidate build revision provenance drifted",
    )
    static_record = require_exact_keys(
        record["static_preparation"],
        {"logical_path", "source", "product_selector", "manifest_sha256", "receipt"},
        "static preparation binding",
    )
    dynamic_record = require_exact_keys(
        record["dynamic_materialization"],
        {"logical_path", "identity", "manifest_sha256", "state", "state_file"},
        "dynamic materialization binding",
    )
    require(static_record["logical_path"] == str(STATIC_PREPARATION_PATH), "static preparation logical path drifted")
    require(static_record["product_selector"] == "primary", "static product selector drifted")
    require(static_record["source"] == {
        "content_sha256": candidate_build["source_content_sha256"],
        "revision": candidate_build["revision"],
    }, "static source binding drifted")
    require(static_record["manifest_sha256"] == static_product["manifest"]["sha256"], "static manifest binding drifted")

    materialization = dynamic_product.get("materialization_state")
    require(isinstance(materialization, dict), "supplied dynamic materialization state is absent")
    require(dynamic_record["logical_path"] == DYNAMIC_STATE_LOGICAL_PATH, "dynamic materialization path drifted")
    require(dynamic_record["identity"] == materialization["identity"], "dynamic materialization state identity drifted")
    require(dynamic_record["manifest_sha256"] == dynamic_product["manifest"]["sha256"], "dynamic materialization manifest binding drifted")
    require(dynamic_record["state"] == materialization["state"], "dynamic materialization state drifted")
    state = _materialization_state_shape(dynamic_record["state"])
    require(state["source_sha256"] == candidate_build["source_content_sha256"], "dynamic materialization source binding drifted")

    retained_static = _validate_static_preparation_file(output_root, static_record["receipt"])
    static_receipt_identity = require_exact_keys(
        static_record["receipt"]["identity"],
        {"path", "sha256", "size", "mode"},
        "static preparation receipt identity",
    )
    require(
        file_record(static_receipt, logical_path=str(STATIC_PREPARATION_PATH)) == static_receipt_identity,
        "supplied static preparation receipt bytes changed",
    )
    current_static = read_json(static_receipt, "supplied static preparation receipt")
    require(_stable_json(retained_static) == _stable_json(current_static), "supplied static preparation receipt changed")

    retained_state = _validate_dynamic_materialization_state_file(output_root, dynamic_record["state_file"])
    state_path = dynamic_product_root / DYNAMIC_STATE_RELATIVE
    state_file_record = require_exact_keys(
        dynamic_record["state_file"], {"logical_path", "identity", "snapshot"}, "dynamic materialization state file"
    )
    require(
        file_record(state_path, logical_path=DYNAMIC_STATE_LOGICAL_PATH) == state_file_record["identity"],
        "supplied dynamic materialization state bytes changed",
    )
    require(retained_state == state and read_json(state_path, "supplied dynamic materialization state") == state,
            "supplied dynamic materialization state changed")

    rebound = _bind_product_provenance(
        static_receipt=static_receipt,
        dynamic_product_root=dynamic_product_root,
        static_product=static_product,
        dynamic_product=dynamic_product,
    )
    require(
        rebound["candidate_build"] == candidate_build
        and rebound["static_preparation"] == {
            key: static_record[key]
            for key in ("logical_path", "source", "product_selector", "manifest_sha256")
        }
        and rebound["dynamic_materialization"] == {
            key: dynamic_record[key]
            for key in ("logical_path", "identity", "manifest_sha256", "state")
        },
        "materialized product provenance no longer reconstructs the selected build identity",
    )


def _snapshot_source_inputs(output_root: Path) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for relative in SOURCE_FILES:
        source = ROOT / relative
        records[relative] = _snapshot_regular(
            output_root,
            source,
            f"{SOURCES_COPY_ROOT}/{relative}",
            relative,
        )
    return records


def _validate_source_inputs(output_root: Path, records: object) -> None:
    require(isinstance(records, dict) and set(records) == set(SOURCE_FILES), "collector source roster drifted")
    for relative in SOURCE_FILES:
        _validate_snapshot(
            output_root,
            records[relative],
            f"collector source {relative}",
            expected_original_path=relative,
            expected_retained_path=f"{SOURCES_COPY_ROOT}/{relative}",
        )


def _header_tree_identity(root: Path) -> dict[str, object]:
    """Return the complete physical header-tree roster without following links."""

    root = physical_directory(root, "pinned musl header tree")
    files: list[dict[str, object]] = []

    def visit(directory: Path) -> None:
        try:
            with os.scandir(directory) as entries:
                ordered = sorted(entries, key=lambda entry: entry.name)
        except OSError as error:
            raise InventoryError(f"cannot enumerate pinned header tree: {directory}") from error
        for entry in ordered:
            path = Path(entry.path)
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as error:
                raise InventoryError(f"cannot inspect pinned header tree entry: {path}") from error
            if stat.S_ISDIR(mode):
                visit(path)
                continue
            require(stat.S_ISREG(mode), f"pinned header tree contains a non-regular entry: {path}")
            relative = path.relative_to(root).as_posix()
            files.append(file_record(path, logical_path=f"include/{relative}"))

    visit(root)
    require(bool(files), "pinned musl header tree is empty")
    return {
        "file_count": len(files),
        "files": files,
        "content_sha256": hashlib.sha256(_stable_json(files)).hexdigest(),
    }


def _validated_header_tree_identity(value: object, description: str) -> dict[str, object]:
    identity = require_exact_keys(value, {"file_count", "files", "content_sha256"}, description)
    require(type(identity["file_count"]) is int and identity["file_count"] > 0, f"{description} count is invalid")
    files = identity["files"]
    require(isinstance(files, list) and len(files) == identity["file_count"], f"{description} roster is malformed")
    previous = ""
    for item in files:
        item = require_exact_keys(item, {"path", "sha256", "size", "mode"}, f"{description} file")
        relative = _relative_path(item["path"], f"{description} file")
        require(relative.startswith("include/") and relative > previous, f"{description} roster is unordered or unsafe")
        previous = relative
        require(
            isinstance(item["sha256"], str) and _SHA256.fullmatch(item["sha256"]) is not None
            and type(item["size"]) is int and item["size"] >= 0
            and type(item["mode"]) is int,
            f"{description} file identity is malformed",
        )
    require(
        isinstance(identity["content_sha256"], str)
        and _SHA256.fullmatch(identity["content_sha256"]) is not None
        and identity["content_sha256"] == hashlib.sha256(_stable_json(files)).hexdigest(),
        f"{description} content digest is invalid",
    )
    return identity


def _header_tree_record(
    source_identity: Mapping[str, object],
    retained_identity: Mapping[str, object],
) -> dict[str, object]:
    """Keep source modes separate from private retained-copy modes."""

    return {
        "source_root": str(MUSL_ROOT / "include"),
        "retained_root": f"{MUSL_COPY_ROOT}/include",
        "source_identity": dict(source_identity),
        "retained_identity": dict(retained_identity),
    }


def _header_tree_identities(record: object) -> tuple[dict[str, object], dict[str, object]]:
    record = require_exact_keys(
        record,
        {"source_root", "retained_root", "source_identity", "retained_identity"},
        "pinned musl complete header tree",
    )
    require(record["source_root"] == str(MUSL_ROOT / "include"), "pinned musl header-tree source root drifted")
    require(record["retained_root"] == f"{MUSL_COPY_ROOT}/include", "pinned musl header-tree retained root drifted")
    source = _validated_header_tree_identity(record["source_identity"], "pinned musl source header tree")
    retained = _validated_header_tree_identity(record["retained_identity"], "retained pinned musl header tree")
    source_files = source["files"]
    retained_files = retained["files"]
    require(isinstance(source_files, list) and isinstance(retained_files, list), "pinned musl header-tree state drifted")
    require(
        [item["path"] for item in source_files] == [item["path"] for item in retained_files],
        "source and retained pinned musl header rosters differ",
    )
    for source_item, retained_item in zip(source_files, retained_files):
        require(
            source_item["sha256"] == retained_item["sha256"] and source_item["size"] == retained_item["size"],
            "source and retained pinned musl header content differs",
        )
    return source, retained


def _validate_header_tree_record(output_root: Path, record: object) -> tuple[dict[str, object], dict[str, object]]:
    source, retained = _header_tree_identities(record)
    record = require_exact_keys(
        record,
        {"source_root", "retained_root", "source_identity", "retained_identity"},
        "pinned musl complete header tree",
    )
    retained_root = physical_directory(output_root / str(record["retained_root"]), "retained pinned musl header tree")
    observed = _header_tree_identity(retained_root)
    require(observed == retained, "retained pinned musl header-tree roster or content changed")
    return source, retained


def _snapshot_musl_inputs(output_root: Path) -> dict[str, object]:
    physical_directory(MUSL_ROOT, "pinned musl root")
    regular_files: dict[str, dict[str, object]] = {}
    for relative in MUSL_REGULAR_FILES:
        regular_files[relative] = _snapshot_regular(
            output_root,
            MUSL_ROOT / relative,
            f"{MUSL_COPY_ROOT}/{relative}",
            str(MUSL_ROOT / relative),
        )
    header_root = physical_directory(MUSL_ROOT / "include", "pinned musl headers")
    source_header_tree = _header_tree_identity(header_root)
    headers: list[dict[str, object]] = []
    files = source_header_tree["files"]
    require(isinstance(files, list), "pinned musl header-tree roster state drifted")
    for item in files:
        item = require_exact_keys(item, {"path", "sha256", "size", "mode"}, "pinned musl header-tree file")
        relative = _relative_path(item["path"], "pinned musl header-tree file")
        require(relative.startswith("include/"), "pinned musl header-tree file is outside include")
        headers.append({
            "relative_path": relative,
            "snapshot": _snapshot_regular(
                output_root,
                MUSL_ROOT / relative,
                f"{MUSL_COPY_ROOT}/{relative}",
                str(MUSL_ROOT / relative),
            ),
        })
    require(_header_tree_identity(header_root) == source_header_tree, "pinned musl header tree changed during capture")
    retained_header_tree = _header_tree_identity(output_root / MUSL_COPY_ROOT / "include")

    loader = MUSL_ROOT / MUSL_LOADER
    try:
        loader_mode = loader.lstat().st_mode
        loader_target = os.readlink(loader)
    except OSError as error:
        raise InventoryError("pinned musl loader alias is unreadable") from error
    require(stat.S_ISLNK(loader_mode), "pinned musl loader is not a symlink")
    require(loader_target == str(MUSL_ROOT / "lib/libc.so"), "pinned musl loader target drifted")
    require(Path(os.path.realpath(loader)) == MUSL_ROOT / "lib/libc.so", "pinned musl loader does not resolve to libc.so")
    compiler = _snapshot_regular(
        output_root,
        MUSL_COMPILER,
        "inputs/toolchain/crabc-x86_64-musl-gcc",
        str(MUSL_COMPILER),
    )
    oracle_manifests = _validate_oracle_manifests_live()
    require(
        oracle_manifests["compiler_wrapper_matches_repository_source"] is True,
        "pinned compiler wrapper differs from repository image wrapper source",
    )
    return {
        "fixed_root": str(MUSL_ROOT),
        "retained_root": MUSL_COPY_ROOT,
        "regular_files": regular_files,
        "headers": headers,
        "header_tree": _header_tree_record(source_header_tree, retained_header_tree),
        "loader": {
            "path": str(loader),
            "target": loader_target,
            "resolves_to": str(MUSL_ROOT / "lib/libc.so"),
        },
        "compiler_wrapper": compiler,
        **oracle_manifests,
    }


def _validate_musl_inputs(
    output_root: Path,
    record: object,
    source_records: Mapping[str, object],
) -> None:
    record = require_exact_keys(
        record,
        {
            "fixed_root", "retained_root", "regular_files", "headers", "loader",
            "header_tree", "compiler_wrapper", "repository_pin", "oracle_manifest", "specs_manifest",
            "compiler_wrapper_matches_repository_source",
        },
        "pinned musl input mapping",
    )
    require(record["fixed_root"] == str(MUSL_ROOT), "pinned musl root drifted")
    require(record["retained_root"] == MUSL_COPY_ROOT, "retained musl root drifted")
    regular_files = record["regular_files"]
    require(isinstance(regular_files, dict) and set(regular_files) == set(MUSL_REGULAR_FILES), "pinned musl regular-file roster drifted")
    for relative in MUSL_REGULAR_FILES:
        _validate_snapshot(
            output_root,
            regular_files[relative],
            f"pinned musl {relative}",
            expected_original_path=str(MUSL_ROOT / relative),
            expected_retained_path=f"{MUSL_COPY_ROOT}/{relative}",
        )
    source_header_tree, retained_header_tree = _validate_header_tree_record(output_root, record["header_tree"])
    headers = record["headers"]
    require(isinstance(headers, list) and headers, "pinned musl header roster drifted")
    source_files = source_header_tree["files"]
    retained_files = retained_header_tree["files"]
    require(isinstance(source_files, list) and isinstance(retained_files, list), "pinned musl header-tree files are malformed")
    require(len(headers) == len(source_files), "pinned musl header snapshot roster is incomplete")
    for item, source_item, retained_item in zip(headers, source_files, retained_files):
        item = require_exact_keys(item, {"relative_path", "snapshot"}, "pinned musl header")
        relative = _relative_path(item["relative_path"], "pinned musl header")
        require(relative.startswith("include/"), "pinned musl header is outside include")
        require(relative == source_item["path"] == retained_item["path"], "pinned musl header snapshot path differs from complete roster")
        _validate_snapshot(
            output_root,
            item["snapshot"],
            f"pinned musl header {relative}",
            expected_original_path=str(MUSL_ROOT / relative),
            expected_retained_path=f"{MUSL_COPY_ROOT}/{relative}",
        )
        snapshot = require_exact_keys(item["snapshot"], {"original", "retained"}, f"pinned musl header {relative} snapshot")
        original = require_exact_keys(snapshot["original"], {"path", "sha256", "size", "mode"}, f"pinned musl header {relative} original")
        retained = require_exact_keys(snapshot["retained"], {"path", "sha256", "size", "mode"}, f"pinned musl header {relative} retained")
        require(
            original == {
                **source_item,
                "path": str(MUSL_ROOT / relative),
            },
            "pinned musl header source snapshot differs from complete roster",
        )
        require(
            retained == {
                **retained_item,
                "path": f"{MUSL_COPY_ROOT}/{relative}",
            },
            "pinned musl header retained snapshot differs from complete roster",
        )
    loader = require_exact_keys(record["loader"], {"path", "target", "resolves_to"}, "pinned musl loader")
    require(
        loader == {
            "path": str(MUSL_ROOT / MUSL_LOADER),
            "target": str(MUSL_ROOT / "lib/libc.so"),
            "resolves_to": str(MUSL_ROOT / "lib/libc.so"),
        },
        "pinned musl loader relationship drifted",
    )
    _validate_snapshot(
        output_root,
        record["compiler_wrapper"],
        "pinned musl compiler wrapper",
        expected_original_path=str(MUSL_COMPILER),
        expected_retained_path="inputs/toolchain/crabc-x86_64-musl-gcc",
    )
    _validate_oracle_manifests_retained(output_root, record, source_records)



def _inspect_shared(
    output_root: Path,
    *,
    name: str,
    artifact_path: Path,
    logical_artifact: str,
    tool_records: Mapping[str, Mapping[str, object]],
    commands: dict[str, object],
    require_public_symbols: bool,
) -> dict[str, object]:
    """Capture raw ELF shape and public dynamic symbols for one shared object."""

    command_specs = (
        ("header", ("-hW",), "readelf"),
        ("program", ("-lW",), "readelf"),
        ("dynamic", ("-dW",), "readelf"),
        ("relocations", ("-rW",), "readelf"),
        ("dynsym", ("--wide", "--dyn-syms"), "readelf"),
    )
    parsed: dict[str, str] = {}
    for suffix, flags, tool_name in command_specs:
        key = f"{name}-{suffix}"
        command = _run_tool(
            output_root,
            key=key,
            tool_name=tool_name,
            arguments=[*flags, str(artifact_path)],
            artifact=logical_artifact,
            tool_record=tool_records[tool_name],
        )
        commands[key] = command
        parsed[suffix] = _read_raw(output_root, command["stdout"], f"{key} stdout")
    header = _readelf_header(parsed["header"], f"{name} ELF")
    require(header["Type"].startswith("DYN "), f"{name} is not an ELF shared object")
    symbols = parse_dynamic_symbols(parsed["dynsym"])
    require(bool(symbols) or not require_public_symbols, f"{name} has no public dynamic symbols")
    return {
        "artifact": logical_artifact,
        "identity": file_record(artifact_path, logical_path=logical_artifact),
        "elf": {
            "header": header,
            "program": _readelf_program(parsed["program"]),
            "dynamic_tags": _readelf_dynamic(parsed["dynamic"]),
            "relocations": _readelf_relocations(parsed["relocations"]),
        },
        "dynamic_symbols": symbols,
        "dynamic_aliases": dynamic_aliases(symbols),
    }


def _inspect_archive(
    output_root: Path,
    *,
    name: str,
    artifact_path: Path,
    logical_artifact: str,
    tool_records: Mapping[str, Mapping[str, object]],
    commands: dict[str, object],
) -> dict[str, object]:
    """Capture archive roster, duplicate nm rows, and per-member ELF outcomes."""

    ar_key = f"{name}-ar"
    ar_command = _run_tool(
        output_root,
        key=ar_key,
        tool_name="ar",
        arguments=["t", str(artifact_path)],
        artifact=logical_artifact,
        tool_record=tool_records["ar"],
    )
    commands[ar_key] = ar_command
    members = parse_archive_members(_read_raw(output_root, ar_command["stdout"], f"{ar_key} stdout"))

    nm_key = f"{name}-nm"
    nm_command = _run_tool(
        output_root,
        key=nm_key,
        tool_name="nm",
        arguments=["-A", "-g", "--defined-only", "--format=posix", str(artifact_path)],
        artifact=logical_artifact,
        tool_record=tool_records["nm"],
        allow_diagnostics=True,
    )
    commands[nm_key] = nm_command
    symbols = parse_static_symbols(
        _read_raw(output_root, nm_command["stdout"], f"{nm_key} stdout"),
        expected_archive=str(artifact_path),
    )
    nm_stderr = _read_raw(output_root, nm_command["stderr"], f"{nm_key} stderr")
    no_global_symbols = parse_nm_no_global_symbols_diagnostics(nm_stderr, members)
    require(bool(symbols), f"{name} has no defined static symbols")
    require_static_members_present(symbols, members)

    headers_key = f"{name}-headers"
    headers_command = _run_tool(
        output_root,
        key=headers_key,
        tool_name="readelf",
        arguments=["-hW", str(artifact_path)],
        artifact=logical_artifact,
        tool_record=tool_records["readelf"],
        allow_diagnostics=True,
        allow_nonzero=True,
    )
    commands[headers_key] = headers_command
    headers_stdout = _read_raw(output_root, headers_command["stdout"], f"{headers_key} stdout")
    headers_stderr = _read_raw(output_root, headers_command["stderr"], f"{headers_key} stderr")
    member_outcomes = parse_archive_member_headers(
        headers_stdout,
        members,
        expected_archive=str(artifact_path),
    )
    complete = (
        headers_command["returncode"] == 0
        and not headers_stderr
        and all(item["outcome"] == "x86_64-elf" for item in member_outcomes)
    )
    binding_outcomes = [
        {
            "name": row["name"],
            "archive_member": row["archive_member"],
            "nm_type": row["nm_type"],
            "binding": row["binding"],
        }
        for row in symbols
        if row["binding"] in {"UNIQUE", "UNCLASSIFIED"}
    ]
    return {
        "artifact": logical_artifact,
        "identity": file_record(artifact_path, logical_path=logical_artifact),
        "archive_members": members,
        "static_symbols": symbols,
        "member_nm_observations": {
            "complete": True,
            "diagnostics_retained": bool(nm_stderr),
            "no_global_defined_symbols": no_global_symbols,
        },
        "member_elf_observations": {
            "complete": complete,
            "diagnostics_retained": bool(headers_stderr),
            "outcomes": member_outcomes,
        },
        "binding_outcomes": binding_outcomes,
        "alias_relationships": {
            "status": "unclassified",
            "reason": (
                "nm raw rows do not retain member occurrence plus section identity; "
                "equal values cannot establish static aliases"
            ),
        },
    }


def _ensure_collection_paths(
    *,
    static_product: Path,
    dynamic_product: Path,
    static_preparation: Path,
) -> None:
    require(static_product == STATIC_PRODUCT_PATH, "collection requires static product at /inputs/static-product")
    require(dynamic_product == DYNAMIC_PRODUCT_PATH, "collection requires dynamic product at /inputs/dynamic-product")
    require(static_preparation == STATIC_PREPARATION_PATH, "collection requires static preparation at /inputs/static-preparation.json")


def _require_native_collection_context() -> None:
    require(platform.system() == "Linux", "collection requires a native Linux execution context")
    require(platform.machine() in {"x86_64", "amd64"}, "collection requires native x86-64 execution")
    require(ROOT == Path("/workspace"), "collection requires the fixed /workspace checkout")
    require(Path.cwd() == Path("/workspace"), "collection requires /workspace as its execution root")


def _fresh_output_root(output_root: Path, work_root: Path) -> Path:
    require(output_root.is_absolute(), "inventory output must be absolute")
    require(work_root == CANONICAL_WORK_ROOT, "inventory work root must be fixed /workspace/.work/x86_64")
    work_root = physical_directory(work_root, "inventory work root")
    try:
        output_root.relative_to(work_root)
    except ValueError as error:
        raise InventoryError("inventory output is outside its declared work root") from error
    parent = output_root.parent
    physical_directory(parent, "inventory output parent")
    require(not output_root.exists(), "inventory output must be a fresh directory")
    try:
        output_root.mkdir(mode=0o700)
    except OSError as error:
        raise InventoryError(f"cannot create inventory output: {output_root}") from error
    return output_root


def _validate_live_snapshot(path: Path, record: object, description: str, *, logical_path: str) -> None:
    record = require_exact_keys(record, {"original", "retained"}, description)
    original = require_exact_keys(record["original"], {"path", "sha256", "size", "mode"}, f"{description} original")
    require(original["path"] == logical_path, f"{description} live path drifted")
    source = physical_regular(path, f"{description} live input")
    observed = file_record(source, logical_path=logical_path)
    require(observed == original, f"{description} changed during collection")


def _verify_live_musl_unchanged(record: Mapping[str, object]) -> None:
    regular_files = record["regular_files"]
    require(isinstance(regular_files, dict), "pinned musl regular files malformed")
    for relative in MUSL_REGULAR_FILES:
        _validate_live_snapshot(
            MUSL_ROOT / relative,
            regular_files[relative],
            f"pinned musl {relative}",
            logical_path=str(MUSL_ROOT / relative),
        )
    headers = record["headers"]
    require(isinstance(headers, list), "pinned musl headers malformed")
    for item in headers:
        item = require_exact_keys(item, {"relative_path", "snapshot"}, "pinned musl header")
        _validate_live_snapshot(
            MUSL_ROOT / str(item["relative_path"]),
            item["snapshot"],
            f"pinned musl header {item['relative_path']}",
            logical_path=str(MUSL_ROOT / str(item["relative_path"])),
        )
    header_tree = record["header_tree"]
    require(isinstance(header_tree, dict), "pinned musl header-tree record is malformed")
    source_header_tree, _retained_header_tree = _header_tree_identities(header_tree)
    require(
        _header_tree_identity(MUSL_ROOT / "include") == source_header_tree,
        "pinned musl header-tree roster or content changed during collection",
    )
    _validate_live_snapshot(
        MUSL_COMPILER,
        record["compiler_wrapper"],
        "pinned musl compiler wrapper",
        logical_path=str(MUSL_COMPILER),
    )
    observed_oracle = _validate_oracle_manifests_live()
    for field in (
        "repository_pin",
        "oracle_manifest",
        "specs_manifest",
        "compiler_wrapper_matches_repository_source",
    ):
        require(record.get(field) == observed_oracle[field], f"pinned musl {field} changed during collection")


def _verify_live_source_unchanged(records: Mapping[str, object]) -> None:
    for relative in SOURCE_FILES:
        record = records[relative]
        _validate_live_snapshot(
            ROOT / relative,
            record,
            f"collector source {relative}",
            logical_path=relative,
        )


def _verify_live_tools_unchanged(records: Mapping[str, Mapping[str, object]]) -> None:
    for name, path in TOOL_PATHS.items():
        _validate_live_snapshot(path, records[name], f"{name} tool", logical_path=str(path))


def collect_inventory(
    *,
    static_product: Path,
    dynamic_product: Path,
    static_preparation: Path,
    output_root: Path,
    work_root: Path,
    image_identity: str,
) -> Path:
    """Collect one source-bound measurement report in a fresh private root."""

    _ensure_collection_paths(
        static_product=static_product,
        dynamic_product=dynamic_product,
        static_preparation=static_preparation,
    )
    _require_native_collection_context()
    require(_IMAGE.fullmatch(image_identity) is not None, "collector image identity is absent or malformed")
    output_root = _fresh_output_root(output_root, work_root)
    try:
        collector_execution_source = collector_source_seal()
        source_inputs = _snapshot_source_inputs(output_root)
        tool_records = _tool_records(output_root)
        musl_inputs = _snapshot_musl_inputs(output_root)
        static_record = _product_record(static_product, logical_root=str(STATIC_PRODUCT_PATH), kind="static")
        dynamic_record = _product_record(dynamic_product, logical_root=str(DYNAMIC_PRODUCT_PATH), kind="dynamic")
        product_provenance = _bind_product_provenance(
            static_receipt=static_preparation,
            dynamic_product_root=dynamic_product,
            static_product=static_record,
            dynamic_product=dynamic_record,
            output_root=output_root,
        )

        commands: dict[str, object] = {}
        reference_shared = _inspect_shared(
            output_root,
            name="reference-shared",
            artifact_path=MUSL_ROOT / "lib/libc.so",
            logical_artifact=str(MUSL_ROOT / "lib/libc.so"),
            tool_records=tool_records,
            commands=commands,
            require_public_symbols=True,
        )
        candidate_shared = _inspect_shared(
            output_root,
            name="candidate-shared",
            artifact_path=dynamic_product / "usr/lib/libc.so",
            logical_artifact=_logical_child(str(DYNAMIC_PRODUCT_PATH), "usr/lib/libc.so"),
            tool_records=tool_records,
            commands=commands,
            require_public_symbols=True,
        )
        candidate_loader = _inspect_shared(
            output_root,
            name="candidate-loader",
            artifact_path=dynamic_product / "lib/ld-crabc-x86_64.so.1",
            logical_artifact=_logical_child(str(DYNAMIC_PRODUCT_PATH), "lib/ld-crabc-x86_64.so.1"),
            tool_records=tool_records,
            commands=commands,
            require_public_symbols=False,
        )
        reference_static = _inspect_archive(
            output_root,
            name="reference-static",
            artifact_path=MUSL_ROOT / "lib/libc.a",
            logical_artifact=str(MUSL_ROOT / "lib/libc.a"),
            tool_records=tool_records,
            commands=commands,
        )
        candidate_static = _inspect_archive(
            output_root,
            name="candidate-static",
            artifact_path=static_product / "usr/lib/libc.a",
            logical_artifact=_logical_child(str(STATIC_PRODUCT_PATH), "usr/lib/libc.a"),
            tool_records=tool_records,
            commands=commands,
        )

        require(
            reference_shared["identity"] == musl_inputs["regular_files"]["lib/libc.so"]["original"],
            "reference shared object changed before its inventory",
        )
        require(
            reference_static["identity"] == musl_inputs["regular_files"]["lib/libc.a"]["original"],
            "reference static archive changed before its inventory",
        )
        require(
            candidate_shared["identity"] == dynamic_record["selection"]["libc_shared"],
            "candidate shared object selection changed before its inventory",
        )
        require(
            candidate_loader["identity"] == dynamic_record["selection"]["loader"],
            "candidate loader selection changed before its inventory",
        )
        require(
            candidate_static["identity"] == static_record["selection"]["libc_archive"],
            "candidate static archive selection changed before its inventory",
        )

        inventory = {
            "reference": {
                "shared": reference_shared,
                "static": reference_static,
                "loader_relationship": musl_inputs["loader"],
            },
            "candidate": {
                "shared": candidate_shared,
                "loader": candidate_loader,
                "static": candidate_static,
                "loader_relationship": dynamic_record["selection"]["loader_alias"],
            },
        }
        triage = {
            "shared_dynamic": compare_dynamic_symbols(
                reference_shared["dynamic_symbols"], candidate_shared["dynamic_symbols"]
            ),
            "static_archive": compare_static_symbols(
                reference_static["static_symbols"], candidate_static["static_symbols"]
            ),
            "disposition": (
                "measurement-only exact differences; no compatibility, family "
                "completion, promotion, or public-support conclusion"
            ),
        }

        # Recheck every mutable input after tool inspection. Read-only mounts make
        # this normally uneventful, but the report must not bless an input that
        # changed after one raw command observed it.
        _verify_live_source_unchanged(source_inputs)
        _verify_live_tools_unchanged(tool_records)
        _verify_live_musl_unchanged(musl_inputs)
        require(
            _product_record(static_product, logical_root=str(STATIC_PRODUCT_PATH), kind="static") == static_record,
            "static product changed during inventory collection",
        )
        require(
            _product_record(dynamic_product, logical_root=str(DYNAMIC_PRODUCT_PATH), kind="dynamic") == dynamic_record,
            "dynamic product changed during inventory collection",
        )
        _bind_product_provenance(
            static_receipt=static_preparation,
            dynamic_product_root=dynamic_product,
            static_product=static_record,
            dynamic_product=dynamic_record,
        )
        require(
            collector_source_seal() == collector_execution_source,
            "collector Git revision or content changed during inventory collection",
        )

        report = {
            "schema": SCHEMA,
            "status": {
                "classification": "measurement-only-not-compatibility-or-promotion",
                "family_completion": False,
                "promotion_ready": False,
                "public_support": False,
            },
            "target": TARGET,
            "image": image_identity,
            "collector_execution_source": collector_execution_source,
            "collector_sources": source_inputs,
            "header_closure": {
                "owner_source": "compat/x86_64/headers_layouts_aggregate.py",
                "owner_report": "compat/x86_64/generated/headers_layouts_aggregate/report.json",
                "source_identity": source_inputs["compat/x86_64/headers_layouts_aggregate.py"],
                "report_identity": source_inputs["compat/x86_64/generated/headers_layouts_aggregate/report.json"],
                "meaning": (
                    "routes the existing native header-closure source/report identity; "
                    "this inventory does not claim header declaration evidence"
                ),
            },
            "product_provenance": product_provenance,
            "inputs": {
                "pinned_musl": musl_inputs,
                "static_product": static_record,
                "dynamic_product": dynamic_record,
            },
            "tools": tool_records,
            "commands": commands,
            "inventories": inventory,
            "triage": triage,
        }
        report_path = output_root / REPORT_NAME
        _write_private(report_path, _stable_json(report))
        return report_path
    except BaseException:
        # A partial report must not be mistaken for an accepted inventory.
        shutil.rmtree(output_root, ignore_errors=True)
        raise


def _repository_musl_pin() -> dict[str, str]:
    path = physical_regular(ROOT / "compat/upstreams.toml", "repository musl pin")
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise InventoryError("repository musl pin is unreadable") from error
    musl = value.get("musl")
    require(isinstance(musl, dict), "repository musl pin is absent")
    expected = {
        "version",
        "source",
        "sha256",
        "fallback_repository",
        "fallback_revision",
    }
    require(set(musl) == expected, "repository musl pin fields drifted")
    for key in expected:
        require(isinstance(musl[key], str) and musl[key], f"repository musl pin {key} is invalid")
    require(musl["version"] == "1.2.6", "repository musl version drifted")
    require(_SHA256.fullmatch(musl["sha256"]) is not None, "repository musl digest is invalid")
    require(_REVISION.fullmatch(musl["fallback_revision"]) is not None, "repository musl fallback revision is invalid")
    return {key: musl[key] for key in sorted(expected)}


def _parse_oracle_manifest(raw: str, pin: Mapping[str, str]) -> dict[str, str]:
    lines = raw.splitlines()
    expected_order = ("format", "version", "source_sha256", "fallback_revision", "architecture")
    require(len(lines) == len(expected_order), "pinned musl oracle manifest line count drifted")
    values: dict[str, str] = {}
    for expected_key, line in zip(expected_order, lines):
        require("=" in line, "pinned musl oracle manifest is malformed")
        key, value = line.split("=", 1)
        require(key == expected_key and value, "pinned musl oracle manifest ordering or value drifted")
        values[key] = value
    require(
        values
        == {
            "format": "crabc-pinned-musl-oracle-v1",
            "version": pin["version"],
            "source_sha256": pin["sha256"],
            "fallback_revision": pin["fallback_revision"],
            "architecture": "x86_64",
        },
        "pinned musl oracle manifest disagrees with repository pin",
    )
    return values


def _parse_specs_manifest(raw: str, specs_digest: str) -> dict[str, str]:
    match = re.fullmatch(
        r"(?P<sha>[0-9a-f]{64})  (?P<path>/opt/musl-1\.2\.6/lib/musl-gcc\.specs)\n",
        raw,
    )
    require(match is not None, "pinned musl specs manifest is malformed")
    require(match.group("sha") == specs_digest, "pinned musl specs manifest digest disagrees with specs")
    return {"sha256": match.group("sha"), "path": match.group("path")}


def _retained_snapshot_bytes(output_root: Path, record: object, description: str) -> bytes:
    record = require_exact_keys(record, {"original", "retained"}, description)
    retained = require_exact_keys(record["retained"], {"path", "sha256", "size", "mode"}, f"{description} retained")
    path = _recorded_relative_file(output_root, retained["path"], f"{description} retained")
    observed = file_record(path, logical_path=retained["path"])
    require(observed == retained, f"{description} retained bytes or mode changed")
    try:
        return path.read_bytes()
    except OSError as error:
        raise InventoryError(f"cannot read {description} retained bytes") from error


def _source_retained_bytes(output_root: Path, source_records: Mapping[str, object], relative: str) -> bytes:
    require(relative in source_records, f"collector source {relative} is absent")
    return _retained_snapshot_bytes(output_root, source_records[relative], f"collector source {relative}")


def _validate_oracle_source_wrapper(source_bytes: bytes, wrapper_bytes: bytes) -> None:
    require(
        wrapper_bytes == source_bytes,
        "pinned compiler wrapper differs from the repository image wrapper source",
    )


def _validate_oracle_manifests_live() -> dict[str, object]:
    pin = _repository_musl_pin()
    oracle = (MUSL_ROOT / ".crabc-oracle").read_text(encoding="utf-8")
    specs = MUSL_ROOT / "lib/musl-gcc.specs"
    specs_manifest = (MUSL_ROOT / ".crabc-musl-gcc-specs.sha256").read_text(encoding="utf-8")
    wrapper = physical_regular(MUSL_COMPILER, "pinned musl compiler wrapper").read_bytes()
    wrapper_source = physical_regular(ROOT / "docker/x86_64-musl-oracle-gcc", "repository oracle wrapper").read_bytes()
    return {
        "repository_pin": pin,
        "oracle_manifest": _parse_oracle_manifest(oracle, pin),
        "specs_manifest": _parse_specs_manifest(specs_manifest, sha256(specs)),
        "compiler_wrapper_matches_repository_source": wrapper == wrapper_source,
    }


def _validate_oracle_manifests_retained(
    output_root: Path,
    record: Mapping[str, object],
    source_records: Mapping[str, object],
) -> None:
    pin = _repository_musl_pin()
    require(record.get("repository_pin") == pin, "pinned musl repository pin drifted")
    oracle_snapshot = record["regular_files"][".crabc-oracle"]
    specs_snapshot = record["regular_files"]["lib/musl-gcc.specs"]
    specs_manifest_snapshot = record["regular_files"][".crabc-musl-gcc-specs.sha256"]
    oracle = _retained_snapshot_bytes(output_root, oracle_snapshot, "pinned musl oracle manifest").decode("utf-8")
    specs_manifest = _retained_snapshot_bytes(output_root, specs_manifest_snapshot, "pinned musl specs manifest").decode("utf-8")
    specs_retained = require_exact_keys(specs_snapshot, {"original", "retained"}, "pinned musl specs snapshot")["retained"]
    require(isinstance(specs_retained, dict), "pinned musl specs retained record malformed")
    specs_digest = specs_retained.get("sha256")
    require(isinstance(specs_digest, str) and _SHA256.fullmatch(specs_digest) is not None, "pinned musl specs retained digest malformed")
    require(record.get("oracle_manifest") == _parse_oracle_manifest(oracle, pin), "retained oracle manifest drifted")
    require(record.get("specs_manifest") == _parse_specs_manifest(specs_manifest, specs_digest), "retained specs manifest drifted")
    wrapper = _retained_snapshot_bytes(output_root, record["compiler_wrapper"], "pinned musl compiler wrapper")
    source_wrapper = _source_retained_bytes(
        output_root,
        source_records,
        "docker/x86_64-musl-oracle-gcc",
    )
    _validate_oracle_source_wrapper(source_wrapper, wrapper)
    require(record.get("compiler_wrapper_matches_repository_source") is True, "pinned compiler wrapper/source binding drifted")


def _validate_tools(output_root: Path, records: object) -> dict[str, dict[str, object]]:
    require(isinstance(records, dict) and set(records) == set(TOOL_PATHS), "tool roster drifted")
    result: dict[str, dict[str, object]] = {}
    for name, path in TOOL_PATHS.items():
        record = records[name]
        _validate_snapshot(
            output_root,
            record,
            f"{name} tool",
            expected_original_path=str(path),
            expected_retained_path=f"{TOOLS_COPY_ROOT}/{name}",
        )
        require(isinstance(record, dict), f"{name} tool record is malformed")
        result[name] = record
    return result


def _validate_current_source_inputs(output_root: Path, records: Mapping[str, object]) -> None:
    _validate_source_inputs(output_root, records)
    for relative in SOURCE_FILES:
        record = require_exact_keys(records[relative], {"original", "retained"}, f"collector source {relative}")
        original = require_exact_keys(record["original"], {"path", "sha256", "size", "mode"}, f"collector source {relative} original")
        current = file_record(ROOT / relative, logical_path=relative)
        require(current == original, f"current collector source changed: {relative}")


def _replay_shared(
    output_root: Path,
    *,
    commands: Mapping[str, object],
    name: str,
    artifact: str,
    artifact_identity: Mapping[str, object],
    tool_records: Mapping[str, Mapping[str, object]],
    require_public_symbols: bool,
) -> dict[str, object]:
    command_specs = (
        ("header", ("-hW",), "readelf"),
        ("program", ("-lW",), "readelf"),
        ("dynamic", ("-dW",), "readelf"),
        ("relocations", ("-rW",), "readelf"),
        ("dynsym", ("--wide", "--dyn-syms"), "readelf"),
    )
    parsed: dict[str, str] = {}
    for suffix, flags, tool_name in command_specs:
        key = f"{name}-{suffix}"
        require(key in commands, f"missing retained command: {key}")
        stdout, _stderr = _validate_command(
            output_root,
            commands[key],
            key=key,
            tool_name=tool_name,
            arguments=[*flags, artifact],
            artifact=artifact,
            artifact_identity=artifact_identity,
            tool_record=tool_records[tool_name],
            diagnostics_allowed=False,
        )
        parsed[suffix] = stdout
    header = _readelf_header(parsed["header"], f"{name} ELF")
    require(header["Type"].startswith("DYN "), f"{name} is not an ELF shared object")
    symbols = parse_dynamic_symbols(parsed["dynsym"])
    require(bool(symbols) or not require_public_symbols, f"{name} has no public dynamic symbols")
    return {
        "artifact": artifact,
        "identity": dict(artifact_identity),
        "elf": {
            "header": header,
            "program": _readelf_program(parsed["program"]),
            "dynamic_tags": _readelf_dynamic(parsed["dynamic"]),
            "relocations": _readelf_relocations(parsed["relocations"]),
        },
        "dynamic_symbols": symbols,
        "dynamic_aliases": dynamic_aliases(symbols),
    }


def _replay_archive(
    output_root: Path,
    *,
    commands: Mapping[str, object],
    name: str,
    artifact: str,
    artifact_identity: Mapping[str, object],
    tool_records: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    ar_key = f"{name}-ar"
    require(ar_key in commands, f"missing retained command: {ar_key}")
    ar_stdout, _ar_stderr = _validate_command(
        output_root,
        commands[ar_key],
        key=ar_key,
        tool_name="ar",
        arguments=["t", artifact],
        artifact=artifact,
        artifact_identity=artifact_identity,
        tool_record=tool_records["ar"],
        diagnostics_allowed=False,
    )
    members = parse_archive_members(ar_stdout)

    nm_key = f"{name}-nm"
    require(nm_key in commands, f"missing retained command: {nm_key}")
    nm_stdout, nm_stderr = _validate_command(
        output_root,
        commands[nm_key],
        key=nm_key,
        tool_name="nm",
        arguments=["-A", "-g", "--defined-only", "--format=posix", artifact],
        artifact=artifact,
        artifact_identity=artifact_identity,
        tool_record=tool_records["nm"],
        diagnostics_allowed=True,
    )
    nm_command = require_exact_keys(
        commands[nm_key],
        {
            "key", "tool", "tool_identity", "argv", "artifact", "artifact_identity", "environment",
            "returncode", "stdout", "stderr", "diagnostics_allowed",
        },
        f"command {nm_key}",
    )
    require(nm_command["returncode"] == 0, f"command {nm_key} did not finish successfully")
    symbols = parse_static_symbols(nm_stdout, expected_archive=artifact)
    no_global_symbols = parse_nm_no_global_symbols_diagnostics(nm_stderr, members)
    require(bool(symbols), f"{name} has no defined static symbols")
    require_static_members_present(symbols, members)

    headers_key = f"{name}-headers"
    require(headers_key in commands, f"missing retained command: {headers_key}")
    headers_stdout, headers_stderr = _validate_command(
        output_root,
        commands[headers_key],
        key=headers_key,
        tool_name="readelf",
        arguments=["-hW", artifact],
        artifact=artifact,
        artifact_identity=artifact_identity,
        tool_record=tool_records["readelf"],
        diagnostics_allowed=True,
    )
    header_command = require_exact_keys(
        commands[headers_key],
        {
            "key", "tool", "tool_identity", "argv", "artifact", "artifact_identity", "environment",
            "returncode", "stdout", "stderr", "diagnostics_allowed",
        },
        f"command {headers_key}",
    )
    outcomes = parse_archive_member_headers(headers_stdout, members, expected_archive=artifact)
    complete = (
        header_command["returncode"] == 0
        and not headers_stderr
        and all(item["outcome"] == "x86_64-elf" for item in outcomes)
    )
    binding_outcomes = [
        {
            "name": row["name"],
            "archive_member": row["archive_member"],
            "nm_type": row["nm_type"],
            "binding": row["binding"],
        }
        for row in symbols
        if row["binding"] in {"UNIQUE", "UNCLASSIFIED"}
    ]
    return {
        "artifact": artifact,
        "identity": dict(artifact_identity),
        "archive_members": members,
        "static_symbols": symbols,
        "member_nm_observations": {
            "complete": True,
            "diagnostics_retained": bool(nm_stderr),
            "no_global_defined_symbols": no_global_symbols,
        },
        "member_elf_observations": {
            "complete": complete,
            "diagnostics_retained": bool(headers_stderr),
            "outcomes": outcomes,
        },
        "binding_outcomes": binding_outcomes,
        "alias_relationships": {
            "status": "unclassified",
            "reason": (
                "nm raw rows do not retain member occurrence plus section identity; "
                "equal values cannot establish static aliases"
            ),
        },
    }


def _expected_command_keys() -> set[str]:
    shared = {
        f"{name}-{part}"
        for name in ("reference-shared", "candidate-shared", "candidate-loader")
        for part in ("header", "program", "dynamic", "relocations", "dynsym")
    }
    static = {
        f"{name}-{part}"
        for name in ("reference-static", "candidate-static")
        for part in ("ar", "nm", "headers")
    }
    return shared | static


def validate_report(
    report_path: Path,
    *,
    static_product: Path,
    dynamic_product: Path,
    static_preparation: Path,
) -> dict[str, object]:
    """Pure host replay of retained raw evidence and supplied sealed products."""

    report_path = physical_regular(report_path, "native ABI inventory report")
    require(report_path.name == REPORT_NAME, "native ABI inventory report has the wrong name")
    output_root = physical_directory(report_path.parent, "native ABI inventory root")
    report = read_json(report_path, "native ABI inventory report")
    require_exact_keys(
        report,
        {
            "schema", "status", "target", "image", "collector_execution_source", "collector_sources", "header_closure",
            "product_provenance", "inputs", "tools", "commands", "inventories", "triage",
        },
        "native ABI inventory report",
    )
    require(report["schema"] == SCHEMA, "native ABI inventory schema drifted")
    require(report["target"] == TARGET, "native ABI inventory target drifted")
    require(isinstance(report["image"], str) and _IMAGE.fullmatch(report["image"]) is not None, "native ABI inventory image drifted")
    _validate_collector_source_seal(report["collector_execution_source"])
    require(
        report["status"]
        == {
            "classification": "measurement-only-not-compatibility-or-promotion",
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        }
        # JSON numbers are not measurement-status booleans, even though
        # Python considers 0 == False. Preserve the exact v1 field types.
        and all(report["status"][field] is False for field in (
            "family_completion", "promotion_ready", "public_support",
        )),
        "native ABI inventory status drifted",
    )

    source_records = report["collector_sources"]
    require(isinstance(source_records, dict), "collector source records are malformed")
    _validate_current_source_inputs(output_root, source_records)
    header_closure = require_exact_keys(
        report["header_closure"],
        {"owner_source", "owner_report", "source_identity", "report_identity", "meaning"},
        "header closure routing",
    )
    require(
        header_closure["owner_source"] == "compat/x86_64/headers_layouts_aggregate.py"
        and header_closure["owner_report"] == "compat/x86_64/generated/headers_layouts_aggregate/report.json"
        and header_closure["source_identity"] == source_records[header_closure["owner_source"]]
        and header_closure["report_identity"] == source_records[header_closure["owner_report"]]
        and header_closure["meaning"]
        == "routes the existing native header-closure source/report identity; this inventory does not claim header declaration evidence",
        "header closure routing drifted",
    )

    tool_records = _validate_tools(output_root, report["tools"])
    inputs = require_exact_keys(report["inputs"], {"pinned_musl", "static_product", "dynamic_product"}, "inventory inputs")
    _validate_musl_inputs(output_root, inputs["pinned_musl"], source_records)

    static_actual = _product_record(static_product, logical_root=str(STATIC_PRODUCT_PATH), kind="static")
    dynamic_actual = _product_record(dynamic_product, logical_root=str(DYNAMIC_PRODUCT_PATH), kind="dynamic")
    require(inputs["static_product"] == static_actual, "supplied static product differs from retained inventory")
    require(inputs["dynamic_product"] == dynamic_actual, "supplied dynamic product differs from retained inventory")
    _validate_product_provenance(
        output_root,
        report["product_provenance"],
        static_receipt=static_preparation,
        dynamic_product_root=dynamic_product,
        static_product=static_actual,
        dynamic_product=dynamic_actual,
    )

    commands = report["commands"]
    require(isinstance(commands, dict) and set(commands) == _expected_command_keys(), "retained command roster drifted")
    musl = inputs["pinned_musl"]
    require(isinstance(musl, dict), "pinned musl input mapping malformed")
    regular_files = musl["regular_files"]
    require(isinstance(regular_files, dict), "pinned musl regular-file mapping malformed")
    reference_shared_identity = require_exact_keys(
        regular_files["lib/libc.so"], {"original", "retained"}, "reference shared snapshot"
    )["original"]
    reference_static_identity = require_exact_keys(
        regular_files["lib/libc.a"], {"original", "retained"}, "reference static snapshot"
    )["original"]
    require(isinstance(reference_shared_identity, dict) and isinstance(reference_static_identity, dict), "reference artifact identity malformed")
    dynamic_selection = dynamic_actual["selection"]
    static_selection = static_actual["selection"]
    require(isinstance(dynamic_selection, dict) and isinstance(static_selection, dict), "candidate selection malformed")

    replayed = {
        "reference": {
            "shared": _replay_shared(
                output_root,
                commands=commands,
                name="reference-shared",
                artifact=str(MUSL_ROOT / "lib/libc.so"),
                artifact_identity=reference_shared_identity,
                tool_records=tool_records,
                require_public_symbols=True,
            ),
            "static": _replay_archive(
                output_root,
                commands=commands,
                name="reference-static",
                artifact=str(MUSL_ROOT / "lib/libc.a"),
                artifact_identity=reference_static_identity,
                tool_records=tool_records,
            ),
            "loader_relationship": musl["loader"],
        },
        "candidate": {
            "shared": _replay_shared(
                output_root,
                commands=commands,
                name="candidate-shared",
                artifact=_logical_child(str(DYNAMIC_PRODUCT_PATH), "usr/lib/libc.so"),
                artifact_identity=dynamic_selection["libc_shared"],
                tool_records=tool_records,
                require_public_symbols=True,
            ),
            "loader": _replay_shared(
                output_root,
                commands=commands,
                name="candidate-loader",
                artifact=_logical_child(str(DYNAMIC_PRODUCT_PATH), "lib/ld-crabc-x86_64.so.1"),
                artifact_identity=dynamic_selection["loader"],
                tool_records=tool_records,
                require_public_symbols=False,
            ),
            "static": _replay_archive(
                output_root,
                commands=commands,
                name="candidate-static",
                artifact=_logical_child(str(STATIC_PRODUCT_PATH), "usr/lib/libc.a"),
                artifact_identity=static_selection["libc_archive"],
                tool_records=tool_records,
            ),
            "loader_relationship": dynamic_selection["loader_alias"],
        },
    }
    require(report["inventories"] == replayed, "retained raw evidence does not reconstruct inventories")
    triage = {
        "shared_dynamic": compare_dynamic_symbols(
            replayed["reference"]["shared"]["dynamic_symbols"],
            replayed["candidate"]["shared"]["dynamic_symbols"],
        ),
        "static_archive": compare_static_symbols(
            replayed["reference"]["static"]["static_symbols"],
            replayed["candidate"]["static"]["static_symbols"],
        ),
        "disposition": (
            "measurement-only exact differences; no compatibility, family "
            "completion, promotion, or public-support conclusion"
        ),
    }
    require(report["triage"] == triage, "retained raw evidence does not reconstruct triage")
    return report


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--collect", action="store_true", help="collect one fresh pinned native measurement report")
    mode.add_argument("--validate-report", type=Path, metavar="REPORT", help="purely replay one retained report")
    parser.add_argument("--static-product", type=Path, help="sealed static owned product")
    parser.add_argument("--dynamic-product", type=Path, help="sealed dynamic owned product")
    parser.add_argument("--static-preparation", type=Path, help="source-bound static preparation receipt")
    parser.add_argument("--output", type=Path, help="fresh output directory for --collect")
    parser.add_argument("--work-root", type=Path, help="declared private .work root for --collect")
    args = parser.parse_args(argv)

    required = {
        "--static-product": args.static_product,
        "--dynamic-product": args.dynamic_product,
        "--static-preparation": args.static_preparation,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        parser.error("required inputs: " + ", ".join(missing))
    assert args.static_product is not None
    assert args.dynamic_product is not None
    assert args.static_preparation is not None

    try:
        if args.collect:
            if args.output is None or args.work_root is None:
                parser.error("--collect requires --output and --work-root")
            image_identity = os.environ.get("CRABC_X86_ABI_IMAGE_ID", "")
            report = collect_inventory(
                static_product=args.static_product,
                dynamic_product=args.dynamic_product,
                static_preparation=args.static_preparation,
                output_root=args.output,
                work_root=args.work_root,
                image_identity=image_identity,
            )
            print(report)
        else:
            require(args.output is None and args.work_root is None, "--validate-report takes no --output or --work-root")
            assert args.validate_report is not None
            validate_report(
                args.validate_report,
                static_product=args.static_product,
                dynamic_product=args.dynamic_product,
                static_preparation=args.static_preparation,
            )
            print(args.validate_report)
        return 0
    except InventoryError as error:
        print(f"native ABI inventory error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
