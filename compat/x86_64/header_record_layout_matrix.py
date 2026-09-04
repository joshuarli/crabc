#!/usr/bin/env python3
"""Generate the native x86 record-byte-layout comparison matrix.

The matrix is compiler-derived: Clang's AST identifies records and fields from
each direct public include, then a second compiler invocation emits the
record-layout dump for only those compiler-discovered complete types.  It
records size, alignment, and named field offsets for both the candidate and
pinned-musl trees.  Exceptional declarations remain explicit facts rather
than being silently omitted; this is layout evidence, not a C ABI provider or
runtime claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
LOCAL_MODULE_DIR = ROOT / "compat" / "x86_64"
if str(LOCAL_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(LOCAL_MODULE_DIR))

import header_callable_inventory as inventory  # noqa: E402


CONTRACT_PATH = ROOT / "compat" / "x86_64" / "header_record_layout_matrix.toml"
SCHEMA = "crabc.x86_64-header-record-layout-matrix-report/v1"
CONTRACT_SCHEMA = "crabc.x86_64-header-record-layout-matrix/v1"
TARGET = "x86_64-unknown-linux-musl"
PLATFORM = "Linux/x86-64 little-endian"
ORACLE = "Pinned musl 1.2.6"
REPORT_SCOPE = {
    "archive_linkage": False,
    "family_promotion": False,
    "public_support": False,
    "runtime": False,
}
NA_CATEGORIES = (
    "incomplete",
    "anonymous-only",
    "bit-field",
    "flexible-tail",
    "non-addressable-field",
)
LAYOUT_TYPE_RE = re.compile(r"^Type: (?P<type>[^\n]+)$", re.MULTILINE)
LAYOUT_SIZE_RE = re.compile(r"^  Size:(?P<size>\d+)$", re.MULTILINE)
LAYOUT_ALIGNMENT_RE = re.compile(r"^  Alignment:(?P<alignment>\d+)$", re.MULTILINE)
LAYOUT_OFFSETS_RE = re.compile(r"^  FieldOffsets: \[(?P<offsets>[^\]]*)\]>", re.MULTILINE)


class RecordLayoutMatrixError(ValueError):
    """The record-layout contract or checked report is unsafe or stale."""


@dataclass(frozen=True)
class MatrixContract:
    schema: str
    public_headers: Path
    generated_report: Path
    callable_inventory: Path
    profiles: tuple[inventory.Profile, ...]
    oracle_not_applicable: Mapping[tuple[str, str], str]
    policy: Mapping[str, bool]
    not_applicable_categories: tuple[str, ...]


@dataclass(frozen=True)
class RecordDecl:
    key: str
    tag: str
    name: str | None
    alias: str | None
    complete: bool
    fields: tuple[Mapping[str, Any], ...]
    source_line: int | None
    force_type: str | None
    context: tuple[str, ...]
    field_path: tuple[str, ...]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecordLayoutMatrixError(message)


def repository_path(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty path")
    relative = Path(value)
    require(not relative.is_absolute() and ".." not in relative.parts and "\\" not in value, f"{location} escapes repository")
    path = ROOT / relative
    require(path.is_file() and not path.is_symlink(), f"{location} is not a regular file: {value}")
    return path


def repository_destination(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty path")
    relative = Path(value)
    require(not relative.is_absolute() and ".." not in relative.parts and "\\" not in value, f"{location} escapes repository")
    parent = ROOT / relative.parent
    require(parent.is_dir() and not parent.is_symlink(), f"{location} parent is unsafe")
    return ROOT / relative


def string_list(value: object, location: str) -> list[str]:
    require(isinstance(value, list) and value, f"{location} must be a nonempty array")
    result: list[str] = []
    for index, item in enumerate(value):
        require(isinstance(item, str) and item, f"{location}[{index}] is invalid")
        result.append(item)
    require(len(result) == len(set(result)), f"{location} contains duplicates")
    return result


def load_contract(path: Path = CONTRACT_PATH) -> MatrixContract:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RecordLayoutMatrixError(f"cannot load {path}: {error}") from error
    require(set(raw) == {"schema", "target", "platform", "oracle", "public_headers", "callable_inventory", "generated_report", "policy", "work_package", "oracle_not_applicable"}, "record-layout contract keys changed")
    require(raw.get("schema") == CONTRACT_SCHEMA, "record-layout contract schema changed")
    require(raw.get("target") == TARGET, "record-layout contract target changed")
    require(raw.get("platform") == PLATFORM, "record-layout contract platform changed")
    require(raw.get("oracle") == ORACLE, "record-layout contract oracle changed")
    policy = raw.get("policy")
    expected_policy = {
        "compiler_ast_json": True,
        "compiler_record_layout_dump": True,
        "header_text_parsing": False,
        "source_layout_truth": True,
        "archive_linkage": False,
        "runtime": False,
        "family_promotion": False,
        "public_support": False,
    }
    require(policy == expected_policy, "record-layout policy changed")
    work_package = raw.get("work_package")
    require(isinstance(work_package, Mapping), "record-layout work package is missing")
    for key in ("target_family", "focused_evidence_command", "negative_scope", "expected_transition"):
        require(isinstance(work_package.get(key), str) and work_package[key], f"work_package.{key} is invalid")
    require(work_package["target_family"] == "libc.headers-layouts", "record-layout family changed")
    require(work_package["focused_evidence_command"] == "./scripts/dev-x86_64.sh header-record-layout-matrix", "record-layout command changed")
    require(string_list(work_package.get("target_obligations"), "work_package.target_obligations") == ["record-byte-layouts"], "record-layout obligations changed")
    require(string_list(work_package.get("not_applicable_categories"), "work_package.not_applicable_categories") == list(NA_CATEGORIES), "record-layout category roster changed")
    public_headers = repository_path(raw.get("public_headers"), "public_headers")
    callable_inventory = repository_path(raw.get("callable_inventory"), "callable_inventory")
    generated_report = repository_destination(raw.get("generated_report"), "generated_report")
    inv_contract = inventory.load_contract()
    require(public_headers == inv_contract.public_headers, "record-layout public header input drifted")
    require(callable_inventory == inv_contract.generated_inventory, "record-layout callable inventory input drifted")
    exceptions: dict[tuple[str, str], str] = {}
    entries = raw.get("oracle_not_applicable")
    require(isinstance(entries, list), "record-layout oracle exceptions are missing")
    for index, entry in enumerate(entries):
        require(isinstance(entry, Mapping), f"oracle_not_applicable[{index}] is invalid")
        header = entry.get("header")
        profile = entry.get("profile")
        reason = entry.get("reason")
        require(isinstance(header, str) and isinstance(profile, str) and isinstance(reason, str) and reason, f"oracle_not_applicable[{index}] is malformed")
        require((header, profile) not in exceptions, "record-layout oracle exception is duplicated")
        exceptions[(header, profile)] = reason
    require(set(exceptions) == {("aio.h", "c11-strict")}, "record-layout oracle exception roster changed")
    return MatrixContract(CONTRACT_SCHEMA, public_headers, generated_report, callable_inventory, inv_contract.profiles, exceptions, expected_policy, NA_CATEGORIES)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def source_header(node: Mapping[str, Any], header_root: Path) -> str | None:
    """Resolve a record declaration's physical source header.

    ``includedFrom`` identifies the include context, not the declaration's
    owner.  The callable inventory intentionally considers that context for
    its own provenance, but using it here turns compact transitive AST records
    such as ``struct flock`` into declarations of every wrapper that includes
    ``fcntl.h``.  Record-layout comparison instead follows only the physical
    location and its spelling/expansion locations.
    """
    location = node.get("loc")
    if not isinstance(location, Mapping):
        return None
    candidates: list[Mapping[str, Any]] = [location]
    for key in ("spellingLoc", "expansionLoc"):
        nested = location.get(key)
        if isinstance(nested, Mapping):
            candidates.append(nested)
    resolved_root = header_root.resolve()
    for candidate in candidates:
        file_name = candidate.get("file")
        if not isinstance(file_name, str) or not file_name or file_name.startswith("<"):
            continue
        try:
            return Path(file_name).resolve().relative_to(resolved_root).as_posix()
        except (OSError, ValueError):
            continue
    return None


def direct_include_header(location: object, header_root: Path, primary_header: str) -> str | None:
    """Recover a compact declaration only when its include context is direct.

    Clang can omit the physical file for a declaration at the start of a
    direct public include.  A primary-header or generated-TU context then
    identifies that direct observation.  An intermediate project header does
    not: it must never turn a transitive record into the wrapper's record.
    This fallback deliberately does not update ``last_physical_header``.
    """
    if not isinstance(location, Mapping):
        return None
    included_from = location.get("includedFrom")
    if not isinstance(included_from, Mapping):
        return None
    file_name = included_from.get("file")
    if not isinstance(file_name, str) or not file_name or file_name.startswith("<"):
        return None
    try:
        included_header = Path(file_name).resolve().relative_to(header_root.resolve()).as_posix()
    except (OSError, ValueError):
        # The compiler's generated translation unit lies outside the header
        # tree, so its direct include is the only public-header context.
        return primary_header
    return primary_header if included_header == primary_header else None


def explicit_location(location: object) -> bool:
    if not isinstance(location, Mapping):
        return False
    candidates = [location]
    for key in ("spellingLoc", "expansionLoc"):
        nested = location.get(key)
        if isinstance(nested, Mapping):
            candidates.append(nested)
    return any(isinstance(item, Mapping) and isinstance(item.get("file"), str) and item["file"] for item in candidates)


def compact_location(location: object) -> bool:
    return isinstance(location, Mapping) and all(isinstance(location.get(key), int) for key in ("offset", "line", "col"))


def child_field_name(parent: Mapping[str, Any], child: Mapping[str, Any]) -> str | None:
    """Find an anonymous/nested record's containing named field from AST types."""
    child_name = child.get("name") if isinstance(child.get("name"), str) else None
    location = child.get("loc")
    line = location.get("line") if isinstance(location, Mapping) else None
    col = location.get("col") if isinstance(location, Mapping) else None
    for field in parent.get("inner", []):
        if not isinstance(field, Mapping) or field.get("kind") != "FieldDecl":
            continue
        name = field.get("name")
        if not isinstance(name, str) or not name:
            continue
        type_info = field.get("type")
        type_name = type_info.get("qualType") if isinstance(type_info, Mapping) else None
        if not isinstance(type_name, str):
            continue
        if child_name and re.search(rf"(?:^|[^A-Za-z0-9_]){re.escape(child_name)}(?:$|[^A-Za-z0-9_])", type_name):
            return name
        if isinstance(line, int) and isinstance(col, int) and f":{line}:{col}" in type_name:
            return name
    return None


def declaration_nodes(ast: Mapping[str, Any], header_root: Path, primary_header: str) -> list[tuple[Mapping[str, Any], str | None, tuple[str, ...], tuple[str, ...]]]:
    result: list[tuple[Mapping[str, Any], str | None, tuple[str, ...], tuple[str, ...]]] = []
    stack: list[tuple[Mapping[str, Any], tuple[str, ...], tuple[str, ...]]] = [(ast, (), ())]
    last_physical_header: str | None = None
    while stack:
        node, context, field_path = stack.pop()
        location = node.get("loc")
        physical = source_header(node, header_root)
        if physical is not None:
            last_physical_header = physical
        elif explicit_location(location):
            last_physical_header = None
        visible = physical
        if visible is None and compact_location(location):
            visible = last_physical_header
        if visible is None:
            visible = direct_include_header(location, header_root, primary_header)
        result.append((node, visible if visible == primary_header else None, context, field_path))
        children = node.get("inner")
        if isinstance(children, list):
            child_context = context
            if node.get("kind") in {"RecordDecl", "CXXRecordDecl"} and isinstance(node.get("name"), str) and node.get("name"):
                child_context = (*context, node["name"])
            stack.extend(
                (
                    child,
                    child_context,
                    (*field_path, child_field_name(node, child)) if child_field_name(node, child) else field_path,
                )
                for child in reversed(children)
                if isinstance(child, Mapping)
            )
    return result


def descendant_ids(node: Mapping[str, Any]) -> set[str]:
    ids: set[str] = set()
    stack: list[Mapping[str, Any]] = [node]
    while stack:
        item = stack.pop()
        for key in ("id",):
            value = item.get(key)
            if isinstance(value, str):
                ids.add(value)
        for key in ("decl", "ownedTagDecl"):
            value = item.get(key)
            if isinstance(value, Mapping) and isinstance(value.get("id"), str):
                ids.add(value["id"])
        children = item.get("inner")
        if isinstance(children, list):
            stack.extend(child for child in children if isinstance(child, Mapping))
    return ids


def direct_records(ast: Mapping[str, Any], header_root: Path, primary_header: str) -> list[RecordDecl]:
    nodes = declaration_nodes(ast, header_root, primary_header)
    aliases: dict[str, list[str]] = {}
    for node, visible, _context, _field_path in nodes:
        if visible != primary_header or node.get("kind") != "TypedefDecl" or node.get("isImplicit") is True:
            continue
        alias = node.get("name")
        if not isinstance(alias, str) or not alias:
            continue
        for identifier in descendant_ids(node):
            aliases.setdefault(identifier, []).append(alias)
    records: list[RecordDecl] = []
    anonymous_ordinal = 0
    for node, visible, context, field_path in nodes:
        if visible != primary_header or node.get("kind") not in {"RecordDecl", "CXXRecordDecl"} or node.get("isImplicit") is True:
            continue
        tag = node.get("tagUsed")
        if not isinstance(tag, str) or tag not in {"struct", "union", "class"}:
            continue
        node_id = node.get("id")
        node_aliases = aliases.get(node_id, []) if isinstance(node_id, str) else []
        node_aliases = sorted(set(node_aliases))
        name = node.get("name") if isinstance(node.get("name"), str) and node.get("name") else None
        alias = None if name is not None else (node_aliases[0] if node_aliases else None)
        line = node.get("loc", {}).get("line") if isinstance(node.get("loc"), Mapping) else None
        line = line if isinstance(line, int) else None
        if name is not None:
            key = f"{tag}:{name}"
            force_type = f"{tag} {name}"
        elif alias is not None:
            key = f"{tag}-typedef:{alias}"
            force_type = alias
        else:
            anonymous_ordinal += 1
            key = f"{tag}-anonymous:{line or 0}:{anonymous_ordinal}"
            force_type = None
        fields = tuple(child for child in node.get("inner", []) if isinstance(child, Mapping) and child.get("kind") == "FieldDecl")
        records.append(RecordDecl(key, tag, name, alias, node.get("completeDefinition") is True, fields, line, force_type, context, field_path))
    selected: dict[str, RecordDecl] = {}
    for record in records:
        prior = selected.get(record.key)
        if prior is None or (record.complete and not prior.complete):
            selected[record.key] = record
    return [selected[key] for key in sorted(selected)]


def field_dispositions(fields: Sequence[Mapping[str, Any]], offsets: Sequence[int]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, field in enumerate(fields):
        name = field.get("name")
        type_info = field.get("type")
        type_name = type_info.get("qualType") if isinstance(type_info, Mapping) else None
        base: dict[str, Any] = {"name": name if isinstance(name, str) and name else None}
        if isinstance(type_name, str):
            base["type"] = type_name
        offset_bits = offsets[index] if index < len(offsets) else None
        base["offset_bits"] = offset_bits
        bitfield = field.get("isBitfield") is True
        flexible = field.get("isFlexibleArrayMember") is True or (isinstance(type_name, str) and re.search(r"\[\]$", type_name) is not None)
        if bitfield:
            base.update({"offset": None, "applicability": "not-applicable", "reason": "bit-field"})
        elif flexible:
            base.update({"offset": None, "applicability": "not-applicable", "reason": "flexible-tail"})
        elif not base["name"] or offset_bits is None or offset_bits % 8:
            base.update({"offset": None, "applicability": "not-applicable", "reason": "non-addressable-field"})
        else:
            base.update({"offset": offset_bits // 8, "applicability": "applicable"})
        result.append(base)
    return result


def parse_layouts(output: str) -> dict[str, dict[str, Any]]:
    layouts: dict[str, dict[str, Any]] = {}
    for block in output.split("*** Dumping AST Record Layout")[1:]:
        type_match = LAYOUT_TYPE_RE.search(block)
        size_match = LAYOUT_SIZE_RE.search(block)
        alignment_match = LAYOUT_ALIGNMENT_RE.search(block)
        offsets_match = LAYOUT_OFFSETS_RE.search(block)
        if not (type_match and size_match and alignment_match and offsets_match):
            continue
        offsets = []
        raw_offsets = offsets_match.group("offsets").strip()
        if raw_offsets:
            offsets = [int(value.strip()) for value in raw_offsets.split(",") if value.strip()]
        type_name = type_match.group("type").strip()
        layouts[type_name] = {
            "size": int(size_match.group("size")) // 8,
            "alignment": int(alignment_match.group("alignment")) // 8,
            "offsets": offsets,
        }
    return layouts


def compiler_command(compiler: str, profile: inventory.Profile, header_root: Path, resource_include: Path, linux_uapi_include: Path, source: Path, *, ast: bool) -> list[str]:
    command = [compiler, "-x", "c" if profile.language == "c" else "c++", f"-std={profile.standard}"]
    if profile.language == "cxx":
        command.append("-nostdinc++")
    command.extend(["-nostdinc", "-I", str(header_root), "-isystem", str(resource_include), "-isystem", str(linux_uapi_include)])
    command.extend(f"-D{define}" for define in profile.defines)
    if ast:
        command.extend(["-Xclang", "-ast-dump=json", "-fsyntax-only"])
    else:
        command.extend(["-Xclang", "-fdump-record-layouts-simple", "-c", "-o", os.devnull])
    command.append(str(source))
    return command


def force_type_for(record: RecordDecl, language: str) -> str | None:
    if record.force_type is None:
        return None
    if language == "cxx" and record.context and record.field_path and record.name:
        outer = f"{record.tag} {record.context[0]}"
        return f"decltype((({outer}*)0)->{'.'.join(record.field_path)})"
    if language == "cxx" and record.context and record.name:
        return f"{record.tag} {'::'.join((*record.context, record.name))}"
    return record.force_type


def run_compiler(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    clean_env = {key: value for key, value in os.environ.items() if key not in {"CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "GCC_EXEC_PREFIX", "GCC_SPECS", "COMPILER_PATH"}}
    return subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env)


def ast_for_header(compiler: str, profile: inventory.Profile, header: str, header_root: Path, resource_include: Path, linux_uapi_include: Path, source: Path) -> Mapping[str, Any]:
    source.write_text(f"#include <{header}>\n", encoding="utf-8")
    result = run_compiler(compiler_command(compiler, profile, header_root, resource_include, linux_uapi_include, source, ast=True))
    require(result.returncode == 0, f"compiler AST failed for {header}:{profile.identifier}: {result.stderr.splitlines()[0] if result.stderr else 'no diagnostic'}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RecordLayoutMatrixError(f"compiler AST is invalid for {header}:{profile.identifier}: {error}") from error
    require(isinstance(value, Mapping), "compiler AST root is invalid")
    return value


def tree_header_profile(compiler: str, profile: inventory.Profile, header: str, header_root: Path, resource_include: Path, linux_uapi_include: Path, work_dir: Path) -> tuple[list[dict[str, Any]], str]:
    ast_source = work_dir / "ast.c"
    ast = ast_for_header(compiler, profile, header, header_root, resource_include, linux_uapi_include, ast_source)
    records = direct_records(ast, header_root, header)
    forceable = [record for record in records if record.complete and force_type_for(record, profile.language) is not None]
    layout_source = work_dir / "layout.c"
    language_prefix = "#include <{}>\n".format(header)
    declarations = "\n".join(f"char crabc_layout_force_{index}[sizeof({force_type_for(record, profile.language)})];" for index, record in enumerate(forceable))
    layout_source.write_text(language_prefix + declarations + "\n", encoding="utf-8")
    layouts_result = run_compiler(compiler_command(compiler, profile, header_root, resource_include, linux_uapi_include, layout_source, ast=False))
    require(layouts_result.returncode == 0, f"record layout compile failed for {header}:{profile.identifier}: {layouts_result.stderr.splitlines()[0] if layouts_result.stderr else 'no diagnostic'}")
    # Clang emits the record dump on stdout in some pinned images and on
    # stderr in others; both streams are compiler output, never header text.
    layouts = parse_layouts(layouts_result.stdout + layouts_result.stderr)
    result: list[dict[str, Any]] = []
    for record in records:
        if not record.complete:
            result.append({"key": record.key, "tag": record.tag, "name": record.name, "alias": record.alias, "applicability": "not-applicable", "reason": "incomplete", "size": None, "alignment": None, "fields": []})
            continue
        if record.force_type is None:
            result.append({"key": record.key, "tag": record.tag, "name": record.name, "alias": record.alias, "applicability": "not-applicable", "reason": "anonymous-only", "size": None, "alignment": None, "fields": []})
            continue
        force_type = force_type_for(record, profile.language)
        layout = layouts.get(force_type or "") or layouts.get(record.force_type or "") or layouts.get(f"{record.tag} {record.alias}")
        if layout is None and profile.language == "cxx" and record.context and record.name:
            nested = [
                value
                for key, value in layouts.items()
                if key.endswith(f"::{record.name}") and record.context[0] in key
            ]
            if len(nested) == 1:
                layout = nested[0]
        require(layout is not None, f"compiler omitted layout for {header}:{profile.identifier}:{record.key}")
        fields = field_dispositions(record.fields, layout["offsets"])
        result.append({"key": record.key, "tag": record.tag, "name": record.name, "alias": record.alias, "applicability": "applicable", "size": layout["size"], "alignment": layout["alignment"], "fields": fields})
    return result, "compiler AST plus -fdump-record-layouts-simple"


def normalized_record(record: Mapping[str, Any]) -> dict[str, Any]:
    normalized = {
        key: record.get(key)
        for key in ("key", "tag", "name", "alias", "applicability", "reason", "size", "alignment", "fields")
        if key in record
    }
    normalized["fields"] = [
        {
            key: field.get(key)
            for key in ("name", "offset", "offset_bits", "applicability", "reason")
            if key in field
        }
        for field in record.get("fields", [])
        if isinstance(field, Mapping)
    ]
    return normalized


def compare_records(candidate: Sequence[Mapping[str, Any]], reference: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    # Anonymous-only and incomplete declarations are explicit non-applicable
    # observations, not comparable byte-layout subjects. Likewise, a named
    # record with an exceptional field remains comparable for its size/alignment
    # and all addressable fields; only the exceptional field itself is omitted
    # from applicability, not the containing record.
    left = {str(record["key"]): normalized_record(record) for record in candidate if record.get("applicability") == "applicable"}
    right = {str(record["key"]): normalized_record(record) for record in reference if record.get("applicability") == "applicable"}
    candidate_only = sorted(set(left) - set(right))
    reference_only = sorted(set(right) - set(left))
    incompatible = sorted(key for key in set(left) & set(right) if left[key] != right[key])
    return {"candidate_only": candidate_only, "candidate_only_count": len(candidate_only), "reference_only": reference_only, "reference_only_count": len(reference_only), "incompatible": incompatible, "incompatible_count": len(incompatible), "matched_count": sum(left[key] == right[key] for key in set(left) & set(right))}


def record_summary(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    categories = Counter()
    field_categories = Counter()
    applicable = 0
    for record in records:
        if record.get("applicability") == "applicable":
            applicable += 1
        else:
            categories[str(record.get("reason"))] += 1
        for field in record.get("fields", []):
            if isinstance(field, Mapping) and field.get("applicability") != "applicable":
                field_categories[str(field.get("reason"))] += 1
    return {"record_count": len(records), "applicable_record_count": applicable, "not_applicable_record_count": len(records) - applicable, "not_applicable_categories": dict(sorted(categories.items())), "not_applicable_field_categories": dict(sorted(field_categories.items()))}


def validate_record_facts(records: object, label: str) -> list[Mapping[str, Any]]:
    """Validate one compiler tree's complete record/field fact schema."""
    require(isinstance(records, list), f"record-layout {label} records are invalid")
    checked: list[Mapping[str, Any]] = []
    keys: set[str] = set()
    for index, record in enumerate(records):
        location = f"record-layout {label} record[{index}]"
        require(isinstance(record, Mapping), f"{location} is invalid")
        required = {"key", "tag", "name", "alias", "applicability", "size", "alignment", "fields"}
        optional = {"reason"}
        require(set(record).issubset(required | optional) and required.issubset(record), f"{location} keys are invalid")
        key = record.get("key")
        require(isinstance(key, str) and key and key not in keys, f"{location} key is invalid or duplicated")
        keys.add(key)
        require(record.get("tag") in {"struct", "union", "class"}, f"{location} tag is invalid")
        require(record.get("name") is None or isinstance(record.get("name"), str), f"{location} name is invalid")
        require(record.get("alias") is None or isinstance(record.get("alias"), str), f"{location} alias is invalid")
        applicability = record.get("applicability")
        require(applicability in {"applicable", "not-applicable"}, f"{location} applicability is invalid")
        fields = record.get("fields")
        require(isinstance(fields, list), f"{location} fields are invalid")
        if applicability == "applicable":
            require(isinstance(record.get("size"), int) and record["size"] >= 0, f"{location} size is invalid")
            require(isinstance(record.get("alignment"), int) and record["alignment"] > 0, f"{location} alignment is invalid")
            require("reason" not in record, f"{location} applicable record has an exception reason")
        else:
            require(record.get("reason") in NA_CATEGORIES, f"{location} exception category is invalid")
            require(record.get("size") is None and record.get("alignment") is None, f"{location} non-applicable record has layout facts")
            require(not fields, f"{location} non-applicable record has fields")
        field_keys: set[str] = set()
        for field_index, field in enumerate(fields):
            field_location = f"{location} field[{field_index}]"
            require(isinstance(field, Mapping), f"{field_location} is invalid")
            field_required = {"name", "offset", "offset_bits", "applicability"}
            field_optional = {"type", "reason"}
            require(set(field).issubset(field_required | field_optional) and field_required.issubset(field), f"{field_location} keys are invalid")
            name = field.get("name")
            require(name is None or isinstance(name, str), f"{field_location} name is invalid")
            if isinstance(name, str):
                require(name not in field_keys, f"{field_location} name is duplicated")
                field_keys.add(name)
            require(field.get("type") is None or isinstance(field.get("type"), str), f"{field_location} type is invalid")
            field_applicability = field.get("applicability")
            require(field_applicability in {"applicable", "not-applicable"}, f"{field_location} applicability is invalid")
            if field_applicability == "applicable":
                require(isinstance(field.get("offset"), int) and field["offset"] >= 0, f"{field_location} offset is invalid")
                require(isinstance(field.get("offset_bits"), int) and field["offset_bits"] >= 0, f"{field_location} bit offset is invalid")
                require("reason" not in field, f"{field_location} applicable field has an exception reason")
            else:
                require(field.get("offset") is None and field.get("reason") in NA_CATEGORIES, f"{field_location} exception facts are invalid")
        checked.append(record)
    return checked


def expected_summary(rows: Sequence[Mapping[str, Any]], candidate_records: Sequence[Mapping[str, Any]], reference_records: Sequence[Mapping[str, Any]], candidate_header_count: int, pinned_header_count: int, profile_count: int) -> dict[str, Any]:
    comparisons = Counter(str(row["comparison"]) for row in rows)
    candidate_summary = record_summary(candidate_records)
    reference_summary = record_summary(reference_records)
    return {
        "candidate_field_categories": dict(sorted(candidate_summary["not_applicable_field_categories"].items())),
        "candidate_public_header_count": candidate_header_count,
        "candidate_record_categories": dict(sorted(candidate_summary["not_applicable_categories"].items())),
        "candidate_record_count": len(candidate_records),
        "comparison_counts": dict(sorted(comparisons.items())),
        "complete": False,
        "incomplete_reasons": [f"{comparisons.get('mismatch', 0)} comparable header/profile rows have record-byte-layout differences", f"{comparisons.get('oracle-not-applicable', 0)} pinned-musl header/profile rows are oracle-not-applicable", f"{comparisons.get('candidate-only-pending-c-abi-policy', 0)} project-only header/profile rows remain pending C ABI policy", "record-byte-layouts remain partial until every applicable named record and field is matched", "archive linkage, runtime behavior, family promotion, and public support remain outside this matrix"],
        "pinned_public_header_count": pinned_header_count,
        "profile_count": profile_count,
        "reference_field_categories": dict(sorted(reference_summary["not_applicable_field_categories"].items())),
        "reference_record_categories": dict(sorted(reference_summary["not_applicable_categories"].items())),
        "reference_record_count": len(reference_records),
        "row_count": len(rows),
    }


def build_report(compiler: str, project_include: Path, musl_include: Path, linux_uapi_include: Path, contract: MatrixContract | None = None) -> dict[str, Any]:
    contract = load_contract() if contract is None else contract
    require(project_include.is_dir() and not project_include.is_symlink(), "project include root is unsafe")
    inventory.require_pinned_musl_include(musl_include)
    inventory.require_pinned_linux_uapi_include(linux_uapi_include)
    pinned_headers = inventory.load_headers(contract.public_headers)
    require(inventory.public_header_paths(musl_include) == pinned_headers, "pinned musl public header tree drifted")
    candidate_headers = inventory.candidate_header_paths(project_include, pinned_headers)
    resource_include = inventory.compiler_resource_include(compiler)
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="crabc-x86-record-layout.") as temporary:
        work_dir = Path(temporary)
        for header in candidate_headers:
            for profile in contract.profiles:
                key = (header, profile.identifier)
                candidate_records, candidate_detail = tree_header_profile(compiler, profile, header, project_include, resource_include, linux_uapi_include, work_dir)
                row: dict[str, Any] = {"header": header, "profile": profile.identifier, "candidate_status": "ok", "candidate_detail": candidate_detail, "candidate": record_summary(candidate_records), "candidate_records": candidate_records}
                if header not in pinned_headers:
                    row.update({"comparison": "candidate-only-pending-c-abi-policy", "reference": None, "reference_records": None, "reference_status": "not-in-pinned-inventory"})
                elif key in contract.oracle_not_applicable:
                    row.update({"comparison": "oracle-not-applicable", "reference": None, "reference_records": None, "reference_status": "oracle-not-applicable", "reference_detail": contract.oracle_not_applicable[key]})
                else:
                    reference_records, reference_detail = tree_header_profile(compiler, profile, header, musl_include, resource_include, linux_uapi_include, work_dir)
                    difference = compare_records(candidate_records, reference_records)
                    comparison = "matched" if difference["candidate_only_count"] == 0 and difference["reference_only_count"] == 0 and difference["incompatible_count"] == 0 else "mismatch"
                    row.update({"comparison": comparison, "difference": difference, "reference": record_summary(reference_records), "reference_records": reference_records, "reference_status": "ok", "reference_detail": reference_detail})
                rows.append(row)
    candidate_records = [record for row in rows for record in row["candidate_records"]]
    reference_records = [record for row in rows for record in (row["reference_records"] or [])]
    summary = expected_summary(rows, candidate_records, reference_records, len(candidate_headers), len(pinned_headers), len(contract.profiles))
    return {
        "schema": SCHEMA,
        "contract_schema": CONTRACT_SCHEMA,
        "target": TARGET,
        "platform": PLATFORM,
        "oracle": ORACLE,
        "inputs": {"compiler": compiler, "callable_inventory_sha256": sha256_file(contract.callable_inventory), "header_record_layout_matrix_contract_sha256": sha256_file(CONTRACT_PATH), "public_header_inventory_sha256": sha256_file(contract.public_headers)},
        "scope": dict(REPORT_SCOPE),
        "profiles": [{"id": profile.identifier, "language": profile.language, "standard": profile.standard, "defines": list(profile.defines)} for profile in contract.profiles],
        "rows": rows,
        "summary": summary,
    }


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def validate_checked_report(report: Mapping[str, Any], contract: MatrixContract | None = None) -> None:
    contract = load_contract() if contract is None else contract
    require(set(report) == {"schema", "contract_schema", "target", "platform", "oracle", "inputs", "scope", "profiles", "rows", "summary"}, "record-layout report keys changed")
    require(report.get("schema") == SCHEMA and report.get("contract_schema") == CONTRACT_SCHEMA, "record-layout report schema changed")
    require(report.get("target") == TARGET and report.get("platform") == PLATFORM and report.get("oracle") == ORACLE, "record-layout report identity changed")
    require(report.get("scope") == REPORT_SCOPE, "record-layout report scope changed")
    inputs = report.get("inputs")
    require(isinstance(inputs, Mapping), "record-layout report inputs are invalid")
    require(inputs.get("header_record_layout_matrix_contract_sha256") == sha256_file(CONTRACT_PATH), "record-layout contract digest is stale")
    require(inputs.get("public_header_inventory_sha256") == sha256_file(contract.public_headers), "record-layout public-header digest is stale")
    require(inputs.get("callable_inventory_sha256") == sha256_file(contract.callable_inventory), "record-layout inventory digest is stale")
    profiles = report.get("profiles")
    expected_profiles = [{"id": profile.identifier, "language": profile.language, "standard": profile.standard, "defines": list(profile.defines)} for profile in contract.profiles]
    require(profiles == expected_profiles, "record-layout profile roster drifted")
    rows = report.get("rows")
    require(isinstance(rows, list), "record-layout rows are invalid")
    pinned_headers = inventory.load_headers(contract.public_headers)
    candidate_headers = inventory.candidate_header_paths(ROOT / "include", pinned_headers)
    candidate_count = len(candidate_headers)
    expected_row_keys = [(header, profile.identifier) for header in candidate_headers for profile in contract.profiles]
    actual_keys = [(row.get("header"), row.get("profile")) for row in rows if isinstance(row, Mapping)]
    require(len(rows) == candidate_count * len(contract.profiles), "record-layout row count drifted")
    require(actual_keys == expected_row_keys, "record-layout row key coverage drifted")
    summary = report.get("summary")
    require(isinstance(summary, Mapping), "record-layout summary is invalid")
    candidate_records: list[Mapping[str, Any]] = []
    reference_records: list[Mapping[str, Any]] = []
    allowed_comparisons = {"matched", "mismatch", "oracle-not-applicable", "candidate-only-pending-c-abi-policy"}
    for row in rows:
        require(isinstance(row, Mapping), "record-layout row is invalid")
        candidate = validate_record_facts(row.get("candidate_records"), "candidate")
        candidate_records.extend(candidate)
        require(row.get("candidate_status") == "ok" and isinstance(row.get("candidate"), Mapping), "record-layout candidate evidence is invalid")
        require(row["candidate"] == record_summary(candidate), "record-layout candidate row summary drifted")
        comparison = row.get("comparison")
        require(comparison in allowed_comparisons, "record-layout comparison is invalid")
        if comparison in {"matched", "mismatch"}:
            reference = validate_record_facts(row.get("reference_records"), "reference")
            reference_records.extend(reference)
            require(row.get("reference_status") == "ok" and isinstance(row.get("reference"), Mapping), "record-layout reference evidence is invalid")
            require(row["reference"] == record_summary(reference), "record-layout reference row summary drifted")
            difference = row.get("difference")
            require(isinstance(difference, Mapping), "record-layout row difference is missing")
            expected_difference = compare_records(candidate, reference)
            require(difference == expected_difference, "record-layout row difference counts drifted")
            expected_comparison = "matched" if not difference["candidate_only_count"] and not difference["reference_only_count"] and not difference["incompatible_count"] else "mismatch"
            require(comparison == expected_comparison, "record-layout row comparison drifted")
        elif comparison == "oracle-not-applicable":
            require(row.get("reference_status") == "oracle-not-applicable" and row.get("reference_records") is None and row.get("reference") is None, "record-layout oracle exception evidence is invalid")
            require(row.get("reference_detail") == contract.oracle_not_applicable.get((row.get("header"), row.get("profile"))), "record-layout oracle exception reason drifted")
            require("difference" not in row, "record-layout oracle exception has a difference")
        else:
            require(row.get("reference_status") == "not-in-pinned-inventory" and row.get("reference_records") is None and row.get("reference") is None, "record-layout project-only evidence is invalid")
            require("difference" not in row, "record-layout project-only row has a difference")
    expected = expected_summary(rows, candidate_records, reference_records, candidate_count, len(pinned_headers), len(contract.profiles))
    require(dict(summary) == expected, "record-layout summary counts or categories drifted")


def check_output(report: Mapping[str, Any], path: Path) -> None:
    require(path.is_file() and not path.is_symlink(), "record-layout checked report is missing or unsafe")
    try:
        current = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RecordLayoutMatrixError(f"cannot read checked record-layout report: {error}") from error
    require(current == report, "record-layout checked report output drifted")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--project-include", type=Path, required=True)
    parser.add_argument("--musl-include", type=Path, required=True)
    parser.add_argument("--linux-uapi-include", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    require(args.check != args.write, "select exactly one of --check or --write")
    contract = load_contract()
    report = build_report(args.compiler, args.project_include, args.musl_include, args.linux_uapi_include, contract)
    validate_checked_report(report, contract)
    if args.write:
        contract.generated_report.write_text(canonical_json(report), encoding="utf-8")
    else:
        check_output(report, contract.generated_report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecordLayoutMatrixError as error:
        print(f"ERROR: x86 header record layout matrix: {error}", file=sys.stderr)
        raise SystemExit(1)
