#!/usr/bin/env python3
"""Validate the source-only Linux/x86-64 mimalloc API coverage ledger.

The existing ``x86_64-api-v3.5.0.json`` contract deliberately inventories only
the 180 ``mi_decl_export`` declarations in ``include/mimalloc.h``.  This
companion ledger records the rest of the pinned public source boundary: the
headers installed by upstream CMake, source-form C++ and rewrite modes, public
types/options/macros, upstream configuration declarations, test inputs, and
the exact limits of every symbol claim.

It is deliberately *not* a compilation, link, ELF-export, Rust-engine, public
ABI, or native-execution proof.  In particular, no preprocessor configuration
is selected by this checker; all x86-64 target-mode and object-symbol statuses
remain explicitly unassessed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat/allocator/x86_64-api-coverage-v3.5.0.json"
BASE_FUNCTION_INVENTORY_PATH = ROOT / "compat/allocator/x86_64-api-v3.5.0.json"
UPSTREAMS_PATH = ROOT / "compat/upstreams.toml"
DEFAULT_ARCHIVE_PATH = ROOT / "compat/allocator/.cache/mimalloc-3.5.0.tar.gz"
RESULT_SCOPE = (
    "Pinned source public-header, configuration-mode, test-input, and source-form "
    "symbol ledger validation only; it does not establish a selected x86_64 "
    "preprocessor/build mode, compilation, linkability, object exports, Rust "
    "implementation coverage, native execution, public ABI, or runtime integration."
)

ROOT_CMAKE_MEMBER = "CMakeLists.txt"
INCLUDE_PREFIX = "include/"
TEST_PREFIX = "test/"
BASE_HEADER_MEMBER = "include/mimalloc.h"
PUBLIC_HEADER_MODE = {
    "include/mimalloc.h": "base-c-api-with-optional-cxx-conveniences",
    "include/mimalloc-new-delete.h": "cxx-global-new-delete-source-definitions",
    "include/mimalloc-override.h": "source-rewrite-macro-header",
    "include/mimalloc-stats.h": "statistics-extension-c-api",
}
TARGET_CONTEXT = {
    "architecture": "x86_64",
    "endianness": "little",
    "rust_target": "x86_64-unknown-linux-musl",
    "system": "linux",
}


class CoverageError(RuntimeError):
    """The checked-in source coverage ledger no longer matches its pin."""


@dataclass(frozen=True)
class NamedSourceItem:
    """One source-anchored identifier without an implementation assertion."""

    name: str
    source_line: int

    def as_json(self) -> dict[str, object]:
        return {"name": self.name, "source_line": self.source_line}


def sha256_bytes(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def names_sha256(records: list[dict[str, object]]) -> str:
    names = [record["name"] for record in records]
    if not all(isinstance(name, str) for name in names):
        raise CoverageError("source name records contain a non-string name")
    return sha256_bytes("\n".join(names).encode("utf-8"))


def source_line(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def relative(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError as error:
        raise CoverageError(f"path is outside the repository: {path}") from error


def artifact_record(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise CoverageError(f"required checked-in artifact is missing: {path}")
    contents = path.read_bytes()
    return {
        "path": relative(path),
        "bytes": len(contents),
        "sha256": sha256_bytes(contents),
    }


def load_mimalloc_pin() -> dict[str, object]:
    try:
        upstreams = tomllib.loads(UPSTREAMS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise CoverageError(f"missing upstream pin file: {UPSTREAMS_PATH}") from error
    pin = upstreams.get("mimalloc")
    if not isinstance(pin, dict):
        raise CoverageError("compat/upstreams.toml has no [mimalloc] pin")
    required = {"archive_root", "revision", "sha256", "version"}
    if not required <= set(pin):
        raise CoverageError("[mimalloc] pin is missing archive identity fields")
    for field in required:
        if not isinstance(pin[field], str):
            raise CoverageError(f"[mimalloc] pin field {field} is not a string")
    return pin


def read_pinned_source_tree(archive_path: Path, pin: dict[str, object]) -> dict[str, bytes]:
    """Read every ledger input directly from the exact pinned source archive."""

    if not archive_path.is_file():
        raise CoverageError(
            f"pinned mimalloc archive is unavailable: {archive_path}; run the native "
            "allocator oracle first to populate compat/allocator/.cache"
        )
    expected_archive_hash = pin["sha256"]
    assert isinstance(expected_archive_hash, str)
    actual_archive_hash = sha256_bytes(archive_path.read_bytes())
    if actual_archive_hash != expected_archive_hash:
        raise CoverageError(
            "mimalloc archive checksum mismatch: "
            f"expected {expected_archive_hash}, got {actual_archive_hash}"
        )

    archive_root = pin["archive_root"]
    assert isinstance(archive_root, str)
    prefix = f"{archive_root}/"
    tree: dict[str, bytes] = {}
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            if not member.name.startswith(prefix):
                continue
            name = member.name.removeprefix(prefix)
            ledger_member = (
                name == ROOT_CMAKE_MEMBER
                or (name.startswith(INCLUDE_PREFIX) and name.endswith(".h"))
                or (name.startswith(TEST_PREFIX) and member.isreg())
            )
            if ledger_member:
                if not member.isreg():
                    raise CoverageError(f"ledger source member is not a regular file: {member.name}")
                if name in tree:
                    raise CoverageError(f"pinned archive has duplicate ledger member: {name}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise CoverageError(f"cannot read pinned source member: {member.name}")
                tree[name] = extracted.read()

    if ROOT_CMAKE_MEMBER not in tree:
        raise CoverageError("pinned archive lacks root CMakeLists.txt")
    if BASE_HEADER_MEMBER not in tree:
        raise CoverageError("pinned archive lacks include/mimalloc.h")
    if not any(name.startswith(TEST_PREFIX) for name in tree):
        raise CoverageError("pinned archive lacks the upstream test directory")
    return tree


def decode_member(tree: dict[str, bytes], member: str) -> str:
    try:
        return tree[member].decode("utf-8")
    except KeyError as error:
        raise CoverageError(f"pinned source lacks required member: {member}") from error
    except UnicodeDecodeError as error:
        raise CoverageError(f"pinned source member is not UTF-8 text: {member}") from error


def strip_c_comments(source: str) -> str:
    """Mask C comments while retaining line offsets and string literals."""

    output: list[str] = []
    index = 0
    state = "code"
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == "/" and following == "/":
                output.extend((" ", " "))
                index += 2
                state = "line-comment"
                continue
            if current == "/" and following == "*":
                output.extend((" ", " "))
                index += 2
                state = "block-comment"
                continue
            output.append(current)
            if current == '"':
                state = "string"
            elif current == "'":
                state = "character"
        elif state == "line-comment":
            output.append("\n" if current == "\n" else " ")
            if current == "\n":
                state = "code"
        elif state == "block-comment":
            if current == "*" and following == "/":
                output.extend((" ", " "))
                index += 2
                state = "code"
                continue
            output.append("\n" if current == "\n" else " ")
        else:
            output.append(current)
            if current == "\\" and following:
                output.append(following)
                index += 2
                continue
            if (state == "string" and current == '"') or (
                state == "character" and current == "'"
            ):
                state = "code"
        index += 1
    if state == "block-comment":
        raise CoverageError("unterminated block comment in pinned source header")
    return "".join(output)


def mask_preprocessor_directives(source: str) -> str:
    """Mask complete directives, including continuations, while retaining lines."""

    output: list[str] = []
    in_directive = False
    for line in source.splitlines(keepends=True):
        directive = in_directive or line.lstrip().startswith("#")
        if directive:
            output.append("".join("\n" if character == "\n" else " " for character in line))
            in_directive = line.rstrip("\r\n").endswith("\\")
        else:
            output.append(line)
            in_directive = False
    return "".join(output)


def source_code(source: str) -> str:
    return mask_preprocessor_directives(strip_c_comments(source))


def checked_named_records(
    records: list[NamedSourceItem],
    *,
    label: str,
) -> list[dict[str, object]]:
    names = [record.name for record in records]
    if len(names) != len(set(names)):
        duplicates = sorted(name for name in set(names) if names.count(name) > 1)
        raise CoverageError(f"duplicate {label}: {', '.join(duplicates)}")
    return [record.as_json() for record in records]


def source_external_functions(header: str, *, member: str) -> list[dict[str, object]]:
    """Extract source-declared ``mi_decl_export`` functions, never ELF symbols."""

    source = source_code(header)
    records: list[NamedSourceItem] = []
    cursor = 0
    while True:
        export_start = source.find("mi_decl_export", cursor)
        if export_start < 0:
            break
        statement_end = source.find(";", export_start)
        if statement_end < 0:
            raise CoverageError(f"unterminated mi_decl_export declaration in {member}")
        statement = source[export_start:statement_end]
        name_match = re.search(r"\b(mi_[A-Za-z0-9_]+)\s*\(", statement)
        if name_match is None:
            raise CoverageError(f"mi_decl_export declaration has no mi_* function in {member}")
        offset = export_start + name_match.start(1)
        records.append(NamedSourceItem(name_match.group(1), source_line(source, offset)))
        cursor = statement_end + 1
    return checked_named_records(records, label=f"source function declarations in {member}")


def source_static_inline_functions(header: str, *, member: str) -> list[dict[str, object]]:
    source = source_code(header)
    records = [
        NamedSourceItem(match.group(1), source_line(source, match.start(1)))
        for match in re.finditer(
            r"\bstatic\s+inline\b[^;{}]*?\b(mi_[A-Za-z0-9_]+)\s*\(",
            source,
            re.DOTALL,
        )
    ]
    return checked_named_records(records, label=f"static inline functions in {member}")


def source_cxx_template_structures(header: str, *, member: str) -> list[dict[str, object]]:
    source = source_code(header)
    records = [
        NamedSourceItem(match.group(1), source_line(source, match.start(1)))
        for match in re.finditer(
            r"\btemplate\s*<[^>]*>\s*struct\s+(mi_[A-Za-z0-9_]+)\b",
            source,
        )
    ]
    return checked_named_records(records, label=f"C++ template structures in {member}")


def source_type_aliases(header: str, *, member: str) -> list[dict[str, object]]:
    """Extract public ``mi_*_t`` and callback aliases with source line anchors."""

    source = strip_c_comments(header)
    records: list[NamedSourceItem] = []
    for match in re.finditer(
        r"\btypedef\s+(?:struct|enum)\b.*?\}\s*(mi_[A-Za-z0-9_]+(?:_t|_fun))\s*;",
        source,
        re.DOTALL,
    ):
        records.append(NamedSourceItem(match.group(1), source_line(source, match.start(1))))
    for match in re.finditer(r"\btypedef\b[^;{}]*;", source, re.DOTALL):
        declaration = match.group(0)
        callback = re.search(
            r"\(\s*(?:mi_cdecl\s+)?(mi_[A-Za-z0-9_]+_fun)\s*\)\s*\(",
            declaration,
        )
        if callback is not None:
            records.append(
                NamedSourceItem(
                    callback.group(1), source_line(source, match.start() + callback.start(1))
                )
            )
            continue
        aliases = list(re.finditer(r"\b(mi_[A-Za-z0-9_]+(?:_t|_fun))\b", declaration))
        if aliases:
            alias = aliases[-1]
            records.append(
                NamedSourceItem(
                    alias.group(1), source_line(source, match.start() + alias.start(1))
                )
            )
    records.sort(key=lambda record: record.source_line)
    return checked_named_records(records, label=f"type aliases in {member}")


def source_type_tags(header: str, *, member: str) -> list[dict[str, object]]:
    """Record public C struct/enum tag names separately from their aliases."""

    source = strip_c_comments(header)
    grouped: dict[str, list[int]] = {}
    for match in re.finditer(
        r"\btypedef\s+(?:struct|enum)\s+(mi_[A-Za-z0-9_]+)\b", source
    ):
        grouped.setdefault(match.group(1), []).append(source_line(source, match.start(1)))
    if not grouped and member == BASE_HEADER_MEMBER:
        raise CoverageError("mimalloc.h has no parsed C type tags")
    return [
        {"name": name, "source_lines": lines}
        for name, lines in grouped.items()
    ]


def source_option_enumerators(header: str) -> list[dict[str, object]]:
    """Inventory the ``mi_option_e`` source form without selecting an option mode."""

    source = strip_c_comments(header)
    enum_match = re.search(
        r"\btypedef\s+enum\s+mi_option_e\s*\{(?P<body>.*?)\}\s*mi_option_t\s*;",
        source,
        re.DOTALL,
    )
    if enum_match is None:
        return []
    records: list[dict[str, object]] = []
    for match in re.finditer(
        r"(?m)^\s*((?:mi_option_[A-Za-z0-9_]+|_mi_option_last))\b"
        r"\s*(?:=\s*([^,\n]+))?\s*,?",
        enum_match.group("body"),
    ):
        name = match.group(1)
        value_source = match.group(2)
        kind = (
            "internal-sentinel"
            if name.startswith("_")
            else "legacy-alias"
            if value_source is not None
            else "runtime-option"
        )
        record: dict[str, object] = {
            "kind": kind,
            "name": name,
            "source_line": source_line(source, enum_match.start("body") + match.start(1)),
        }
        if value_source is not None:
            record["value_source"] = value_source.strip()
        records.append(record)
    names = [record["name"] for record in records]
    if len(names) != len(set(names)):
        raise CoverageError("duplicate mi_option_e enumerator in mimalloc.h")
    return records


def source_macro_definitions(header: str) -> list[dict[str, object]]:
    """List macro names and source lines without evaluating conditional branches."""

    source = strip_c_comments(header)
    grouped: dict[str, list[int]] = {}
    for match in re.finditer(
        r"(?m)^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b", source
    ):
        grouped.setdefault(match.group(1), []).append(source_line(source, match.start(1)))
    return [
        {"name": name, "source_lines": lines}
        for name, lines in grouped.items()
    ]


def source_cxx_operator_definitions(header: str) -> list[dict[str, object]]:
    """Record C++ operator source forms, never their mangled object symbols."""

    source = source_code(header)
    records: list[dict[str, object]] = []
    for match in re.finditer(r"\boperator\s+(new|delete)(\[\])?\s*\(", source):
        records.append(
            {
                "operator": match.group(1) + (match.group(2) or ""),
                "source_line": source_line(source, match.start(1)),
            }
        )
    return records


def installed_public_headers(root_cmake: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for match in re.finditer(
        r"(?m)^\s*install\s*\(\s*FILES\s+"
        r"(include/[A-Za-z0-9_.-]+\.h)\s+DESTINATION\s+\$\{mi_install_incdir\}\s*\)",
        root_cmake,
    ):
        records.append(
            {
                "member": match.group(1),
                "source_line": source_line(root_cmake, match.start(1)),
            }
        )
    members = [record["member"] for record in records]
    if len(members) != len(set(members)):
        raise CoverageError("root CMake installs a public header more than once")
    if not records:
        raise CoverageError("root CMake has no parsed public header install declarations")
    return records


def cmake_mode_declarations(root_cmake: str) -> list[dict[str, object]]:
    """Record only initial upstream MI_* cache declarations, not resolved modes."""

    records: list[dict[str, object]] = []
    for line_number, line in enumerate(root_cmake.splitlines(), start=1):
        option = re.match(
            r"\s*option\(\s*(MI_[A-Za-z0-9_]+)\b.*\s+(ON|OFF|\"\")\s*\)\s*$",
            line,
        )
        if option is not None:
            records.append(
                {
                    "declaration_kind": "cmake-option",
                    "default_source_token": option.group(2),
                    "name": option.group(1),
                    "source_line": line_number,
                }
            )
            continue
        cache = re.match(
            r"\s*set\(\s*(MI_[A-Za-z0-9_]+)\s+(\"[^\"]*\"|\S+)\s+"
            r"CACHE\s+STRING\b",
            line,
        )
        if cache is not None:
            records.append(
                {
                    "declaration_kind": "cmake-cache-string",
                    "default_source_token": cache.group(2),
                    "name": cache.group(1),
                    "source_line": line_number,
                }
            )
    names = [record["name"] for record in records]
    if len(names) != len(set(names)):
        raise CoverageError("duplicate initial MI_* CMake cache declaration")
    if not records:
        raise CoverageError("no initial MI_* CMake cache declarations were parsed")
    return records


def root_cmake_test_targets(root_cmake: str) -> list[dict[str, object]]:
    """Inventory the root test-target source forms without running them."""

    records: list[dict[str, object]] = []
    foreach = re.search(
        r"(?m)^\s*foreach\s*\(\s*TEST_NAME\s+([^)]+)\)", root_cmake
    )
    if foreach is None:
        raise CoverageError("root CMake has no TEST_NAME test-target foreach declaration")
    names = re.findall(r"[A-Za-z0-9-]+", foreach.group(1))
    if not names:
        raise CoverageError("root CMake TEST_NAME list is empty")
    line = source_line(root_cmake, foreach.start(1))
    records.extend(
        {
            "name": name,
            "source_line": line,
            "source_member": f"test/test-{name}.c",
            "source_form": "root-cmake-test-name-foreach",
        }
        for name in names
    )

    for match in re.finditer(
        r"(?m)^\s*add_executable\(mimalloc-test-([A-Za-z0-9-]+)\s+"
        r"(test/[A-Za-z0-9_.-]+)\)",
        root_cmake,
    ):
        records.append(
            {
                "name": match.group(1),
                "source_line": source_line(root_cmake, match.start(1)),
                "source_member": match.group(2),
                "source_form": "root-cmake-explicit-test-target",
            }
        )
    names = [record["name"] for record in records]
    if len(names) != len(set(names)):
        raise CoverageError("duplicate root CMake test target name")
    return records


def standalone_consumer_test_targets(test_cmake: str) -> list[dict[str, object]]:
    """Inventory test/CMakeLists consumer targets without evaluating CMake."""

    records: list[dict[str, object]] = []
    for match in re.finditer(
        r"(?m)^\s*add_executable\(\s*([A-Za-z0-9_-]+)\s+"
        r"([A-Za-z0-9_.-]+)",
        test_cmake,
    ):
        records.append(
            {
                "name": match.group(1),
                "source_line": source_line(test_cmake, match.start(1)),
                "source_member": f"test/{match.group(2)}",
                "source_form": "test-cmake-installed-consumer-target",
            }
        )
    names = [record["name"] for record in records]
    if len(names) != len(set(names)):
        raise CoverageError("duplicate test/CMakeLists consumer target name")
    if not records:
        raise CoverageError("test/CMakeLists has no parsed consumer test targets")
    return records


def member_record(member: str, contents: bytes) -> dict[str, object]:
    return {"bytes": len(contents), "member": member, "sha256": sha256_bytes(contents)}


def test_member_kind(member: str) -> str:
    suffix = Path(member).suffix
    if member.endswith("CMakeLists.txt"):
        return "cmake-build-description"
    if suffix == ".c":
        return "c-source"
    if suffix == ".cpp":
        return "cxx-source"
    if suffix == ".h":
        return "c-or-cxx-header"
    if suffix == ".md":
        return "documentation"
    return "other-test-input"


def source_header_surface(
    member: str,
    contents: bytes,
    install_line: int,
    *,
    base_function_summary: dict[str, object],
) -> dict[str, object]:
    """Return one installed-header source surface with no active mode claim."""

    header = contents.decode("utf-8")
    external_functions = source_external_functions(header, member=member)
    static_inline_functions = source_static_inline_functions(header, member=member)
    type_aliases = source_type_aliases(header, member=member)
    type_tags = source_type_tags(header, member=member)
    macros = source_macro_definitions(header)
    cxx_templates = source_cxx_template_structures(header, member=member)
    cxx_operators = source_cxx_operator_definitions(header)
    option_enumerators = source_option_enumerators(header) if member == BASE_HEADER_MEMBER else []

    external_surface: dict[str, object]
    if member == BASE_HEADER_MEMBER:
        if (
            len(external_functions) != base_function_summary["source_declared_function_count"]
            or names_sha256(external_functions)
            != base_function_summary["source_declared_function_names_sha256"]
        ):
            raise CoverageError("base C function source parser disagrees with its ledger summary")
        external_surface = {
            "checked_in_inventory": base_function_summary["checked_in_inventory"],
            "names_sha256": base_function_summary["source_declared_function_names_sha256"],
            "source_declared_function_count": base_function_summary[
                "source_declared_function_count"
            ],
            "source_form": "mi_decl_export function declarations",
            "symbol_disposition": "native-object-export-unassessed",
        }
    else:
        external_surface = {
            "declarations": external_functions,
            "names_sha256": names_sha256(external_functions),
            "source_declared_function_count": len(external_functions),
            "source_form": "mi_decl_export function declarations",
            "symbol_disposition": "native-object-export-unassessed",
        }

    return {
        "c_external_function_surface": external_surface,
        "c_static_inline_functions": static_inline_functions,
        "c_type_tags": type_tags,
        "c_type_aliases": type_aliases,
        "cxx_operator_source_definitions": cxx_operators,
        "cxx_template_structures": cxx_templates,
        "installation": "root-cmake-installed-public-header",
        "macro_definitions": macros,
        "member": member,
        "mode": {
            "source_form": PUBLIC_HEADER_MODE[member],
            "x86_64_preprocessor_selection": "not-assessed",
        },
        "runtime_option_enumerators": option_enumerators,
        "source": {"bytes": len(contents), "sha256": sha256_bytes(contents)},
        "source_line_of_root_cmake_install": install_line,
    }


def base_function_inventory_summary(base_header: bytes) -> dict[str, object]:
    """Cross-check the older narrow inventory before the broader ledger uses it."""

    try:
        base_contract = json.loads(BASE_FUNCTION_INVENTORY_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise CoverageError(
            f"missing target-local base function inventory: {BASE_FUNCTION_INVENTORY_PATH}"
        ) from error
    if not isinstance(base_contract, dict):
        raise CoverageError("target-local base function inventory is not a JSON object")
    if base_contract.get("target_context") != TARGET_CONTEXT:
        raise CoverageError("base function inventory target context changed")
    source = base_contract.get("source")
    if not isinstance(source, dict) or source.get("member") != BASE_HEADER_MEMBER:
        raise CoverageError("base function inventory does not identify include/mimalloc.h")
    header_hash = sha256_bytes(base_header)
    if source.get("header_sha256") != header_hash:
        raise CoverageError("base function inventory header hash disagrees with pinned source")

    source_functions = source_external_functions(
        base_header.decode("utf-8"), member=BASE_HEADER_MEMBER
    )
    count = len(source_functions)
    digest = names_sha256(source_functions)
    if base_contract.get("declaration_count") != count:
        raise CoverageError("base function inventory declaration count disagrees with pinned source")
    if base_contract.get("declaration_names_sha256") != digest:
        raise CoverageError("base function inventory declaration digest disagrees with pinned source")

    return {
        "checked_in_inventory": artifact_record(BASE_FUNCTION_INVENTORY_PATH),
        "source_declared_function_count": count,
        "source_declared_function_names_sha256": digest,
    }


def source_symbol_dispositions(header_surfaces: list[dict[str, object]]) -> list[dict[str, object]]:
    """Classify source forms without turning them into link/export claims."""

    by_member = {surface["member"]: surface for surface in header_surfaces}
    base = by_member[BASE_HEADER_MEMBER]
    stats = by_member["include/mimalloc-stats.h"]
    override = by_member["include/mimalloc-override.h"]
    new_delete = by_member["include/mimalloc-new-delete.h"]
    base_external = base["c_external_function_surface"]
    stats_external = stats["c_external_function_surface"]
    assert isinstance(base_external, dict)
    assert isinstance(stats_external, dict)
    return [
        {
            "entry_count": base_external["source_declared_function_count"],
            "native_x86_64_object_symbol_status": "not-assessed",
            "source_form": "mimalloc.h mi_decl_export function declarations",
            "surface": "base-c-functions",
        },
        {
            "entry_count": stats_external["source_declared_function_count"],
            "native_x86_64_object_symbol_status": "not-assessed",
            "source_form": "mimalloc-stats.h mi_decl_export function declarations",
            "surface": "statistics-extension-functions",
        },
        {
            "entry_count": len(base["c_static_inline_functions"]),
            "native_x86_64_object_symbol_status": "not-assessed",
            "source_form": "static inline C helper definitions",
            "surface": "base-header-inline-helpers",
        },
        {
            "entry_count": len(stats["c_static_inline_functions"]),
            "native_x86_64_object_symbol_status": "not-assessed",
            "source_form": "static inline C statistics helper definitions",
            "surface": "statistics-header-inline-helpers",
        },
        {
            "entry_count": len(base["cxx_template_structures"]),
            "native_x86_64_object_symbol_status": "not-assessed",
            "source_form": "optional C++ template structures",
            "surface": "base-header-cxx-templates",
        },
        {
            "entry_count": len(new_delete["cxx_operator_source_definitions"]),
            "native_x86_64_object_symbol_status": "not-assessed",
            "source_form": "C++ global operator source definitions",
            "surface": "new-delete-header-cxx-operators",
        },
        {
            "entry_count": len(
                [
                    macro
                    for macro in override["macro_definitions"]
                    if macro["name"] != "MIMALLOC_OVERRIDE_H"
                ]
            ),
            "native_x86_64_object_symbol_status": "not-assessed",
            "source_form": "preprocessor source-rewrite definitions",
            "surface": "override-header-rewrite-macros",
        },
        {
            "entry_count": sum(
                len(surface["c_type_aliases"])
                + len(surface["c_type_tags"])
                + len(surface["runtime_option_enumerators"])
                + len(surface["macro_definitions"])
                for surface in header_surfaces
            ),
            "native_x86_64_object_symbol_status": "not-an-object-symbol-inventory",
            "source_form": "C type tags and aliases, runtime option enumerators, and preprocessor definitions",
            "surface": "type-option-and-macro-source-forms",
        },
    ]


def expected_contract(archive_path: Path) -> dict[str, object]:
    pin = load_mimalloc_pin()
    tree = read_pinned_source_tree(archive_path, pin)
    root_cmake = decode_member(tree, ROOT_CMAKE_MEMBER)
    installed_headers = installed_public_headers(root_cmake)
    installed_header_members = [record["member"] for record in installed_headers]
    if set(installed_header_members) != set(PUBLIC_HEADER_MODE):
        raise CoverageError(
            "root CMake installed public-header list changed; review the x86-64 source boundary"
        )
    for member in installed_header_members:
        if member not in tree:
            raise CoverageError(f"root CMake installs a header absent from the archive: {member}")

    base_summary = base_function_inventory_summary(tree[BASE_HEADER_MEMBER])
    header_surfaces = [
        source_header_surface(
            record["member"],
            tree[record["member"]],
            record["source_line"],
            base_function_summary=base_summary,
        )
        for record in installed_headers
    ]
    header_surfaces.sort(key=lambda surface: surface["member"])

    all_include_headers = sorted(
        name for name in tree if name.startswith(INCLUDE_PREFIX) and name.endswith(".h")
    )
    noninstalled_include_headers = [
        name for name in all_include_headers if name not in installed_header_members
    ]
    test_members = sorted(name for name in tree if name.startswith(TEST_PREFIX))

    return {
        "base_c_function_inventory": base_summary,
        "build_mode_declarations": {
            "declarations": cmake_mode_declarations(root_cmake),
            "resolution_status": "not-assessed",
            "scope": (
                "Initial MI_* option and CACHE STRING declarations in the pinned root "
                "CMakeLists.txt; they are not resolved x86_64 build settings."
            ),
        },
        "coverage": {
            "c-or-cxx-compilation": "not-assessed",
            "native-x86_64-execution": "not-assessed",
            "native-x86_64-linkability": "not-assessed",
            "native-x86_64-object-symbol-inventory": "not-assessed",
            "overall_status": "incomplete",
            "rust-engine-implementation": "not-assessed",
            "source-inventory": "complete-for-listed-pinned-source-members-only",
            "target-preprocessor-selection": "not-assessed",
        },
        "format": 1,
        "header_surfaces": header_surfaces,
        "integration_boundary": {
            "crabc_libc_exports": "not-assessed",
            "crabc_mimalloc_implementation": "not-assessed",
            "native_object_export_inventory": "not-assessed",
            "public_c_api_adapter": "not-assessed",
            "public_x86_64_runtime_support": "not-claimed",
            "verification": (
                "This ledger verifies pinned source inventory only. It does not establish "
                "a selected x86_64 preprocessor/build mode, compilation, linkability, ELF "
                "exports, Rust implementation coverage, public ABI, behavioral parity, "
                "test execution, stress coverage, or performance qualification."
            ),
        },
        "kind": "mimalloc-x86_64-public-api-mode-test-symbol-coverage-ledger",
        "maturity": "source-surface-coverage-foundation",
        "profile": "linux-x86_64-mimalloc-source-public-surface",
        "scope": {
            "included": [
                "Every include/*.h member installed by the pinned root CMake install(FILES ...) declarations.",
                "The existing target-local include/mimalloc.h mi_decl_export declaration inventory, cross-checked against the same archive.",
                "Public C type aliases, runtime option enumerators, macro definitions, optional C++ source forms, and the public statistics extension source forms.",
                "Initial root-CMake MI_* configuration declarations and all pinned test/ members and CMake target source forms.",
            ],
            "noninstalled_include_boundary": (
                "include/mimalloc/*.h members are recorded only as source-tree members absent "
                "from the pinned root CMake public install list; this does not classify other "
                "packaging systems or claim an internal ABI boundary."
            ),
            "excluded": [
                "CMake-generated package metadata and compiled artifacts.",
                "A selected compiler, preprocessor, CMake, static/shared/object, TLS, override, sanitizer, or optimization mode.",
                "ELF symbols, C++ mangled symbols, linkability, native execution, adapter coverage, Rust implementation coverage, and public crabc integration.",
            ],
        },
        "source": {
            "all_include_headers": [member_record(name, tree[name]) for name in all_include_headers],
            "archive_sha256": pin["sha256"],
            "noninstalled_include_headers": [
                member_record(name, tree[name]) for name in noninstalled_include_headers
            ],
            "root_cmake": member_record(ROOT_CMAKE_MEMBER, tree[ROOT_CMAKE_MEMBER]),
            "test_members": [member_record(name, tree[name]) for name in test_members],
        },
        "symbol_dispositions": source_symbol_dispositions(header_surfaces),
        "target_context": TARGET_CONTEXT,
        "test_source_inventory": {
            "native_x86_64_execution_status": "not-assessed",
            "root_cmake_test_targets": root_cmake_test_targets(root_cmake),
            "scope": (
                "Pinned source members and CMake target declarations only; this is not a "
                "compilation, execution, pass/fail, adapter-selection, or stress result."
            ),
            "standalone_consumer_test_targets": standalone_consumer_test_targets(
                decode_member(tree, "test/CMakeLists.txt")
            ),
        },
        "upstream": {
            "archive_root": pin["archive_root"],
            "revision": pin["revision"],
            "version": pin["version"],
        },
    }


def load_contract() -> dict[str, object]:
    try:
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise CoverageError(f"missing checked-in coverage ledger: {CONTRACT_PATH}") from error
    if not isinstance(contract, dict):
        raise CoverageError("x86_64 API coverage ledger must be a JSON object")
    return contract


def check_contract(archive_path: Path) -> None:
    observed = expected_contract(archive_path)
    checked_in = load_contract()
    if checked_in != observed:
        raise CoverageError(
            "x86_64 public API/mode/test/symbol source ledger drifted from pinned mimalloc "
            "v3.5.0; review the source boundary and update the checked-in ledger deliberately"
        )


def checked_contract_result(archive_path: Path) -> dict[str, object]:
    """Validate the checked-in ledger and return only its source-only result.

    A caller may attach this result to a larger x86-64 oracle report, but the
    result itself remains source provenance.  It does not turn a header,
    CMake-mode, test-input, or source-form symbol inventory into an active
    target configuration, compiled artifact, or execution claim.
    """

    check_contract(archive_path)
    contract = load_contract()
    target = contract.get("target_context")
    coverage = contract.get("coverage")
    source = contract.get("source")
    header_surfaces = contract.get("header_surfaces")
    modes = contract.get("build_mode_declarations")
    dispositions = contract.get("symbol_dispositions")
    base_functions = contract.get("base_c_function_inventory")
    if not isinstance(target, dict) or target != TARGET_CONTEXT:
        raise CoverageError("x86_64 API coverage ledger target context changed")
    if not isinstance(coverage, dict) or coverage.get("overall_status") != "incomplete":
        raise CoverageError("x86_64 API coverage ledger must remain incomplete")
    if not isinstance(source, dict):
        raise CoverageError("x86_64 API coverage ledger source record is invalid")
    if not isinstance(header_surfaces, list) or not header_surfaces:
        raise CoverageError("x86_64 API coverage ledger has no header surfaces")
    if not isinstance(modes, dict):
        raise CoverageError("x86_64 API coverage ledger mode record is invalid")
    declarations = modes.get("declarations")
    if not isinstance(declarations, list) or not declarations:
        raise CoverageError("x86_64 API coverage ledger has no mode declarations")
    if not isinstance(dispositions, list) or not dispositions:
        raise CoverageError("x86_64 API coverage ledger has no symbol dispositions")
    if not isinstance(base_functions, dict):
        raise CoverageError("x86_64 API coverage ledger base API record is invalid")

    all_headers = source.get("all_include_headers")
    test_members = source.get("test_members")
    root_cmake = source.get("root_cmake")
    if (
        not isinstance(all_headers, list)
        or not all_headers
        or not isinstance(test_members, list)
        or not test_members
        or not isinstance(root_cmake, dict)
    ):
        raise CoverageError("x86_64 API coverage ledger source-member inventory is invalid")

    base_count = base_functions.get("source_declared_function_count")
    if type(base_count) is not int or base_count <= 0:
        raise CoverageError("x86_64 API coverage ledger base function count is invalid")
    extension_count = 0
    for surface in header_surfaces:
        if not isinstance(surface, dict):
            raise CoverageError("x86_64 API coverage ledger header surface is invalid")
        member = surface.get("member")
        function_surface = surface.get("c_external_function_surface")
        if not isinstance(member, str) or not isinstance(function_surface, dict):
            raise CoverageError("x86_64 API coverage ledger function surface is invalid")
        count = function_surface.get("source_declared_function_count")
        if type(count) is not int or count < 0:
            raise CoverageError("x86_64 API coverage ledger function count is invalid")
        if member != BASE_HEADER_MEMBER:
            extension_count += count

    return {
        "build_mode_declaration_count": len(declarations),
        "contract": {
            "path": CONTRACT_PATH.relative_to(ROOT).as_posix(),
            "sha256": sha256_bytes(CONTRACT_PATH.read_bytes()),
        },
        "header_surface_count": len(header_surfaces),
        "overall_status": coverage["overall_status"],
        "profile": contract["profile"],
        "scope": RESULT_SCOPE,
        "source_declared_function_count": base_count + extension_count,
        "source_member_count": 1 + len(all_headers) + len(test_members),
        "status": "passed",
        "symbol_disposition_count": len(dispositions),
        "target": dict(target),
        "test_member_count": len(test_members),
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive",
        type=Path,
        default=DEFAULT_ARCHIVE_PATH,
        help="path to the SHA-256-pinned mimalloc v3.5.0 archive",
    )
    parser.add_argument(
        "--print-observed",
        action="store_true",
        help="print the source-derived ledger instead of checking the checked-in artifact",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    if arguments.print_observed:
        print(json.dumps(expected_contract(arguments.archive), indent=2))
        return 0
    check_contract(arguments.archive)
    print("allocator x86_64 public API/mode/test/symbol source ledger: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CoverageError as error:
        raise SystemExit(f"allocator x86_64 public API/mode/test/symbol source ledger: FAIL: {error}")
