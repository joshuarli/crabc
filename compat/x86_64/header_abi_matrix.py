#!/usr/bin/env python3
"""Build the finite native x86 all-public-header declaration-form matrix.

This is a compiler-derived accounting layer for ``libc.headers-layouts``.  It
uses the same isolated direct-include profiles as the callable inventory, but
retains source-level function prototype/linkage spellings plus named typedef,
record, enum, variable, and macro-replacement facts. It deliberately records
differences instead of treating a raw type spelling difference as ABI parity
or ABI drift. Archive extraction, record-byte layouts, runtime behavior, and
family promotion remain separate obligations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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
MODULE_DIRECTORY = ROOT / "compat" / "x86_64"
if str(MODULE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(MODULE_DIRECTORY))

import header_callable_inventory as callable_inventory


CONTRACT_PATH = MODULE_DIRECTORY / "header_abi_matrix.toml"
SCHEMA = "crabc.x86_64-header-abi-matrix-report/v1"
CONTRACT_SCHEMA = "crabc.x86_64-header-abi-matrix/v1"
TARGET = "x86_64-unknown-linux-musl"
PLATFORM = "Linux/x86-64 little-endian"
ORACLE = "Pinned musl 1.2.6"
FACT_KINDS = frozenset({"enum", "function", "macro", "record", "typedef", "variable"})
ANONYMOUS_TYPE_LOCATION = re.compile(
    r"\(unnamed at (?P<path>.+?):(?P<line>[0-9]+):(?P<column>[0-9]+)\)"
)
POLICY = {
    "compiler_ast_json": True,
    "compiler_preprocessor_records": True,
    "header_text_parsing": False,
    "direct_public_include_visibility": True,
    "callable_prototypes": True,
    "named_noncallable_declarations": True,
    "record_byte_layouts": False,
    "archive_linkage": False,
    "runtime": False,
    "family_promotion": False,
    "public_support": False,
}
REPORT_SCOPE = {
    "compiler_derived": True,
    "direct_public_include_visibility": True,
    "callable_prototypes": True,
    "named_noncallable_declarations": True,
    "macro_replacement_forms": True,
    "record_byte_layouts": False,
    "archive_linkage": False,
    "runtime": False,
    "family_promotion": False,
    "public_support": False,
}
WORK_PACKAGE_KEYS = {
    "target_family",
    "target_obligations",
    "blocker",
    "prerequisites",
    "dependent_work",
    "baseline_contract",
    "source_owners",
    "focused_evidence_command",
    "family_aggregate_command",
    "product_command",
    "negative_scope",
    "expected_transition",
    "evidence",
}


class HeaderAbiMatrixError(ValueError):
    """The finite header ABI comparison contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HeaderAbiMatrixError(message)


@dataclass(frozen=True)
class MatrixContract:
    """Trusted finite inputs for one all-public-header comparison pass."""

    public_headers: Path
    callable_inventory: Path
    generated_report: Path
    profiles: tuple[callable_inventory.Profile, ...]
    oracle_not_applicable: Mapping[tuple[str, str], str]
    work_package: Mapping[str, Any]


def repository_path(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty path")
    relative = Path(value)
    require(not relative.is_absolute() and ".." not in relative.parts, f"{location} escapes the repository")
    result = ROOT / relative
    require(result.is_file() and not result.is_symlink(), f"{location} is not a regular repository file: {value}")
    return result


def repository_destination(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty path")
    relative = Path(value)
    require(not relative.is_absolute() and ".." not in relative.parts, f"{location} escapes the repository")
    result = ROOT / relative
    parent = result.parent
    while parent != ROOT and not parent.exists():
        parent = parent.parent
    require(parent.is_dir() and not parent.is_symlink(), f"{location} parent is unsafe: {relative.parent}")
    return result


def string_list(value: object, location: str, *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{location} must be an array")
    result: list[str] = []
    for index, item in enumerate(value):
        require(isinstance(item, str) and item, f"{location}[{index}] is invalid")
        result.append(item)
    require(allow_empty or bool(result), f"{location} must not be empty")
    require(len(result) == len(set(result)), f"{location} has duplicates")
    return result


def load_contract(path: Path = CONTRACT_PATH) -> MatrixContract:
    """Load the work package before invoking a compiler or writing a report."""
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise HeaderAbiMatrixError(f"cannot load {path.relative_to(ROOT)}: {error}") from error
    require(isinstance(raw, Mapping), "header ABI matrix contract must be a table")
    expected_keys = {
        "schema",
        "target",
        "platform",
        "oracle",
        "public_headers",
        "callable_inventory",
        "generated_report",
        "policy",
        "work_package",
        "oracle_not_applicable",
    }
    require(set(raw) == expected_keys, "header ABI matrix contract keys changed")
    require(raw["schema"] == CONTRACT_SCHEMA, "header ABI matrix contract schema changed")
    require(raw["target"] == TARGET, "header ABI matrix target changed")
    require(raw["platform"] == PLATFORM, "header ABI matrix platform changed")
    require(raw["oracle"] == ORACLE, "header ABI matrix oracle changed")
    require(raw["policy"] == POLICY, "header ABI matrix policy changed")

    public_headers = repository_path(raw["public_headers"], "public_headers")
    callable_records = repository_path(raw["callable_inventory"], "callable_inventory")
    generated_report = repository_destination(raw["generated_report"], "generated_report")
    inventory_contract = callable_inventory.load_contract()
    require(public_headers == inventory_contract.public_headers, "header ABI matrix public-header input drifted")
    require(callable_records == inventory_contract.generated_inventory, "header ABI matrix callable inventory drifted")

    work_package = raw["work_package"]
    require(isinstance(work_package, Mapping), "header ABI matrix work package is invalid")
    require(set(work_package) == WORK_PACKAGE_KEYS, "header ABI matrix work package keys changed")
    require(work_package["target_family"] == "libc.headers-layouts", "header ABI matrix family drifted")
    require(
        string_list(work_package["target_obligations"], "work_package.target_obligations")
        == ["callable-prototype-layout", "noncallable-header-abi"],
        "header ABI matrix obligation order changed",
    )
    require(
        string_list(work_package["prerequisites"], "work_package.prerequisites")
        == ["oracle.musl-toolchain", "libc.errno-tls"],
        "header ABI matrix prerequisite order changed",
    )
    for field in (
        "blocker",
        "baseline_contract",
        "focused_evidence_command",
        "family_aggregate_command",
        "product_command",
        "negative_scope",
        "expected_transition",
    ):
        require(isinstance(work_package[field], str) and work_package[field], f"work_package.{field} is invalid")
    require(
        work_package["focused_evidence_command"] == "./scripts/dev-x86_64.sh header-abi-matrix",
        "header ABI matrix focused command drifted",
    )
    require(
        work_package["family_aggregate_command"]
        == "./scripts/dev-x86_64.sh campaign-family libc.headers-layouts",
        "header ABI matrix aggregate command drifted",
    )
    require(
        string_list(work_package["evidence"], "work_package.evidence")
        == ["generated-x86-prototype-layout-matrix"],
        "header ABI matrix evidence identifier drifted",
    )
    string_list(work_package["dependent_work"], "work_package.dependent_work")
    source_owners = set(string_list(work_package["source_owners"], "work_package.source_owners"))
    for owner in (
        "compat/x86_64/header_abi_matrix.toml",
        "compat/x86_64/header_abi_matrix.py",
        "compat/x86_64/run_header_abi_matrix.sh",
        "compat/x86_64/tests/test_header_abi_matrix.py",
        "compat/x86_64/header_callable_inventory.toml",
        "compat/x86_64/header_callable_inventory.py",
        "compat/x86_64/header_callable_inventory.json",
        "compat/x86_64/public_headers.txt",
        "compat/x86_64/headers-layouts-foundation.toml",
        "compat/x86_64/parity.toml",
        "compat/x86_64/validate_parity_ledger.py",
        "scripts/dev-x86_64.sh",
    ):
        require(owner in source_owners, f"header ABI matrix work package omits {owner}")

    raw_exceptions = raw["oracle_not_applicable"]
    require(isinstance(raw_exceptions, list), "header ABI matrix oracle exceptions are invalid")
    exceptions: dict[tuple[str, str], str] = {}
    for index, entry in enumerate(raw_exceptions):
        location = f"oracle_not_applicable[{index}]"
        require(isinstance(entry, Mapping) and set(entry) == {"header", "profile", "reason"}, f"{location} keys changed")
        header = entry["header"]
        profile = entry["profile"]
        reason = entry["reason"]
        require(isinstance(header, str) and header, f"{location}.header is invalid")
        require(isinstance(profile, str) and profile, f"{location}.profile is invalid")
        require(isinstance(reason, str) and reason, f"{location}.reason is invalid")
        key = (header, profile)
        require(key not in exceptions, f"{location} duplicates an oracle exception")
        exceptions[key] = reason
    require(
        tuple(exceptions)
        == (("aio.h", "c11-strict"),),
        "header ABI matrix oracle exception roster changed",
    )
    return MatrixContract(
        public_headers=public_headers,
        callable_inventory=callable_records,
        generated_report=generated_report,
        profiles=inventory_contract.profiles,
        oracle_not_applicable=exceptions,
        work_package=dict(work_package),
    )


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def signature_digest(signature: str) -> str:
    return hashlib.sha256(signature.encode("utf-8")).hexdigest()


def fact(kind: str, name: str, signature: str) -> dict[str, str]:
    """Make one stable, compiler-derived named declaration-form fact."""
    require(kind in FACT_KINDS, f"unsupported ABI fact kind: {kind}")
    require(name and "\n" not in name, "ABI fact name is invalid")
    require(signature and "\n" not in signature, "ABI fact signature is invalid")
    return {
        "kind": kind,
        "name": name,
        "signature": signature,
        "signature_sha256": signature_digest(signature),
    }


def source_header(node: Mapping[str, Any], header_root: Path) -> str | None:
    return callable_inventory.source_path_for_location(node.get("loc"), header_root)


def has_explicit_source_file(location: object) -> bool:
    """Distinguish an omitted compact-AST path from a known foreign source."""

    if not isinstance(location, Mapping):
        return False
    candidates: list[object] = [location]
    for key in ("spellingLoc", "expansionLoc"):
        nested = location.get(key)
        if isinstance(nested, Mapping):
            candidates.append(nested)
    return any(
        isinstance(candidate, Mapping)
        and isinstance(candidate.get("file"), str)
        and bool(candidate["file"])
        for candidate in candidates
    )


def is_compact_source_location(location: object) -> bool:
    """Recognize a source-coordinate record with its repeated file omitted."""

    return (
        isinstance(location, Mapping)
        and isinstance(location.get("offset"), int)
        and isinstance(location.get("col"), int)
        and isinstance(location.get("line"), int)
    )


def normalize_type_spelling(
    value: str, path_roots: Sequence[tuple[Path, str]]
) -> str:
    """Replace compiler absolute anonymous-type paths with stable root labels."""

    resolved_roots = [(root.resolve(), label) for root, label in path_roots]

    def replace(match: re.Match[str]) -> str:
        source = Path(match["path"])
        try:
            resolved_source = source.resolve()
        except OSError:
            resolved_source = source
        for root, label in resolved_roots:
            try:
                relative = resolved_source.relative_to(root).as_posix()
            except ValueError:
                continue
            return f"(unnamed at {label}/{relative}:{match['line']}:{match['column']})"
        # The compiler-provided path can only be an input outside the three
        # controlled roots. Preserve its basename and position for review
        # without leaking a machine-specific checkout prefix into the report.
        return f"(unnamed at external/{source.name}:{match['line']}:{match['column']})"

    return ANONYMOUS_TYPE_LOCATION.sub(replace, value)


def qualified_type(
    node: Mapping[str, Any], path_roots: Sequence[tuple[Path, str]] = ()
) -> str | None:
    type_info = node.get("type")
    if not isinstance(type_info, Mapping):
        return None
    value = type_info.get("qualType")
    if not isinstance(value, str) or not value:
        return None
    return normalize_type_spelling(value, path_roots)


def constant_expression_value(node: Mapping[str, Any]) -> str | None:
    """Return Clang's evaluated integer value from a declaration subtree."""

    direct = node.get("value")
    if isinstance(direct, str) and direct:
        return direct
    stack = [child for child in node.get("inner", []) if isinstance(child, Mapping)]
    while stack:
        child = stack.pop()
        value = child.get("value")
        if child.get("kind") in {"ConstantExpr", "IntegerLiteral"} and isinstance(value, str) and value:
            return value
        stack.extend(grandchild for grandchild in child.get("inner", []) if isinstance(grandchild, Mapping))
    return None


def field_signature(
    node: Mapping[str, Any], path_roots: Sequence[tuple[Path, str]] = ()
) -> str | None:
    name = node.get("name")
    type_name = qualified_type(node, path_roots)
    if not isinstance(name, str) or not name or type_name is None:
        return None
    bit_width = node.get("bitWidth")
    suffix = ""
    if isinstance(bit_width, Mapping):
        value = bit_width.get("value")
        if isinstance(value, str) and value:
            suffix = f":{value}"
    if node.get("isBitfield") is True:
        value = constant_expression_value(node)
        require(value is not None, f"compiler bitfield width is missing for {name}")
        suffix = f":{value}"
    return f"{name}:{type_name}{suffix}"


def record_signature(
    node: Mapping[str, Any], path_roots: Sequence[tuple[Path, str]] = ()
) -> str | None:
    tag = node.get("tagUsed")
    require(isinstance(tag, str) and tag in {"struct", "union"}, "record tag is invalid")
    if node.get("completeDefinition") is not True:
        return f"{tag};"
    fields = [
        signature
        for child in node.get("inner", [])
        if isinstance(child, Mapping) and child.get("kind") == "FieldDecl"
        for signature in [field_signature(child, path_roots)]
        if signature is not None
    ]
    return f"{tag}" + "{" + ",".join(fields) + "}"


def enum_signature(node: Mapping[str, Any]) -> str:
    values: list[str] = []
    for child in node.get("inner", []):
        if not isinstance(child, Mapping) or child.get("kind") != "EnumConstantDecl":
            continue
        name = child.get("name")
        if not isinstance(name, str) or not name:
            continue
        value = constant_expression_value(child)
        rendered = value if value is not None else "<implicit>"
        values.append(f"{name}={rendered}")
    return "enum{" + ",".join(values) + "}"


def function_signature(
    node: Mapping[str, Any], path_roots: Sequence[tuple[Path, str]] = ()
) -> str | None:
    type_name = qualified_type(node, path_roots)
    if type_name is None:
        return None
    mangled = node.get("mangledName")
    if isinstance(mangled, str) and mangled:
        return f"{type_name}|mangled={mangled}"
    return type_name


def fact_priority(entry: Mapping[str, str]) -> tuple[int, str]:
    signature = entry["signature"]
    return (1 if entry["kind"] == "record" and "{" in signature else 0, signature)


def canonical_facts(records: Iterable[Mapping[str, str]]) -> list[dict[str, str]]:
    """Collapse repeated AST declarations without relying on compiler node IDs."""
    selected: dict[tuple[str, str], dict[str, str]] = {}
    for raw in records:
        entry = fact(str(raw["kind"]), str(raw["name"]), str(raw["signature"]))
        key = (entry["kind"], entry["name"])
        prior = selected.get(key)
        if prior is None or fact_priority(entry) > fact_priority(prior):
            selected[key] = entry
    return [selected[key] for key in sorted(selected)]


def discover_ast_facts(
    ast: Mapping[str, Any],
    header_root: Path,
    primary_header: str | None = None,
    path_roots: Sequence[tuple[Path, str]] | None = None,
) -> list[dict[str, str]]:
    """Extract named declarations visible through one isolated direct include.

    Clang's compact JSON AST can omit a repeated file path after another node
    from the same direct include. The direct header is still a compiler-known
    visibility boundary, so retain such a declaration under ``primary_header``
    rather than dropping its ABI fact.
    """
    discovered: list[dict[str, str]] = []
    path_roots = ((header_root, "public"),) if path_roots is None else path_roots
    stack: list[tuple[Mapping[str, Any], bool]] = [(ast, False)]
    last_header_provenance: str | None = None
    while stack:
        node, inside_function = stack.pop()
        kind = node.get("kind")
        child_inside_function = inside_function or kind == "FunctionDecl"
        children = node.get("inner")
        if isinstance(children, list):
            stack.extend(
                (child, child_inside_function)
                for child in reversed(children)
                if isinstance(child, Mapping)
            )
        location = node.get("loc")
        physical_header = source_header(node, header_root)
        if physical_header is not None:
            last_header_provenance = physical_header
        elif has_explicit_source_file(location):
            last_header_provenance = None
        if kind not in {
            "TypedefDecl",
            "RecordDecl",
            "CXXRecordDecl",
            "EnumDecl",
            "VarDecl",
            "FunctionDecl",
        }:
            continue
        if kind == "VarDecl" and inside_function:
            continue
        visible_header = physical_header
        if (
            visible_header is None
            and primary_header is not None
            and last_header_provenance is not None
            and is_compact_source_location(location)
        ):
            visible_header = last_header_provenance
        if visible_header is None:
            continue
        name = node.get("name")
        if not isinstance(name, str) or not name:
            continue
        if kind == "TypedefDecl":
            signature = qualified_type(node, path_roots)
            if signature is not None:
                discovered.append(fact("typedef", name, signature))
        elif kind in {"RecordDecl", "CXXRecordDecl"}:
            signature = record_signature(node, path_roots)
            if signature is not None:
                discovered.append(fact("record", name, signature))
        elif kind == "EnumDecl":
            discovered.append(fact("enum", name, enum_signature(node)))
        elif kind == "VarDecl":
            signature = qualified_type(node, path_roots)
            if signature is not None:
                discovered.append(fact("variable", name, signature))
        elif kind == "FunctionDecl":
            signature = function_signature(node, path_roots)
            if signature is not None:
                discovered.append(fact("function", name, signature))
    return canonical_facts(discovered)


def macro_definition(line: str) -> tuple[str, str] | None:
    """Parse a compiler-emitted -dD record, never an input header line."""
    prefix = "#define "
    if not line.startswith(prefix):
        return None
    definition = line[len(prefix) :]
    index = 0
    while index < len(definition) and (definition[index].isalnum() or definition[index] == "_"):
        index += 1
    name = definition[:index]
    if not name:
        return None
    form = "function-like" if index < len(definition) and definition[index] == "(" else "object-like"
    return (name, f"{form}:{definition[index:]}")


def macro_undefinition(line: str) -> str | None:
    """Read a compiler-emitted macro state removal."""

    prefix = "#undef "
    if not line.startswith(prefix):
        return None
    name = line[len(prefix) :].strip()
    if not name or any(not (character.isalnum() or character == "_") for character in name):
        return None
    return name


def discover_macro_facts(preprocessed: str, header_root: Path) -> list[dict[str, str]]:
    """Extract final active macro replacement forms with compiler provenance."""
    current_path: Path | None = None
    resolved_root = header_root.resolve()
    active: dict[str, dict[str, str]] = {}
    for raw_line in preprocessed.splitlines():
        marker = callable_inventory.preprocessor_marker_path(raw_line)
        if marker is not None:
            current_path = None
            if not marker.startswith("<"):
                try:
                    candidate = Path(marker).resolve()
                    candidate.relative_to(resolved_root)
                    current_path = candidate
                except (OSError, ValueError):
                    current_path = None
            continue
        undefined = macro_undefinition(raw_line)
        if undefined is not None:
            active.pop(undefined, None)
            continue
        macro = macro_definition(raw_line)
        if macro is not None:
            name, signature = macro
            if current_path is None:
                active.pop(name, None)
            else:
                active[name] = fact("macro", name, signature)
    return canonical_facts(active.values())


def compare_facts(
    candidate_facts: Iterable[Mapping[str, str]], reference_facts: Iterable[Mapping[str, str]]
) -> dict[str, Any]:
    """Compare compiler-emitted declaration forms without hiding their spelling."""
    candidate = {(str(fact["kind"]), str(fact["name"])): str(fact["signature"]) for fact in candidate_facts}
    reference = {(str(fact["kind"]), str(fact["name"])): str(fact["signature"]) for fact in reference_facts}
    candidate_only = [
        {"kind": kind, "name": name, "signature": candidate[(kind, name)]}
        for kind, name in sorted(set(candidate) - set(reference))
    ]
    reference_only = [
        {"kind": kind, "name": name, "signature": reference[(kind, name)]}
        for kind, name in sorted(set(reference) - set(candidate))
    ]
    incompatible = [
        {
            "candidate_signature": candidate[(kind, name)],
            "kind": kind,
            "name": name,
            "reference_signature": reference[(kind, name)],
        }
        for kind, name in sorted(set(candidate) & set(reference))
        if candidate[(kind, name)] != reference[(kind, name)]
    ]
    matched_count = sum(
        1
        for key in set(candidate) & set(reference)
        if candidate[key] == reference[key]
    )
    return {
        "candidate_only": candidate_only,
        "candidate_only_count": len(candidate_only),
        "incompatible": incompatible,
        "incompatible_count": len(incompatible),
        "matched_count": matched_count,
        "reference_only": reference_only,
        "reference_only_count": len(reference_only),
    }


def facts_summary(records: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    rendered = json.dumps(list(records), separators=(",", ":"), sort_keys=True)
    return {
        "count": len(records),
        "kind_counts": dict(sorted(Counter(record["kind"] for record in records).items())),
        "sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
    }


def compiler_profile(
    *,
    compiler: str,
    profile: callable_inventory.Profile,
    header: str,
    header_root: Path,
    resource_include: Path,
    linux_uapi_include: Path,
    work_dir: Path,
) -> tuple[str, str, list[dict[str, str]]]:
    source = work_dir / ("probe.cpp" if profile.language == "cxx" else "probe.c")
    source.write_text(f"#include <{header}>\n", encoding="utf-8")
    ast_result = subprocess.run(
        callable_inventory.compiler_command(
            compiler,
            profile,
            header_root,
            resource_include,
            linux_uapi_include,
            source,
            ast=True,
            preprocess=False,
        ),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if ast_result.returncode != 0:
        diagnostic = next((line.strip() for line in ast_result.stderr.splitlines() if line.strip()), "compiler produced no diagnostic")
        return ("failed", diagnostic, [])
    try:
        ast = json.loads(ast_result.stdout)
    except json.JSONDecodeError as error:
        raise HeaderAbiMatrixError(f"compiler did not emit JSON AST for {header}:{profile.identifier}: {error}") from error
    require(isinstance(ast, Mapping), f"compiler AST root is invalid for {header}:{profile.identifier}")

    macro_result = subprocess.run(
        callable_inventory.compiler_command(
            compiler,
            profile,
            header_root,
            resource_include,
            linux_uapi_include,
            source,
            ast=False,
            preprocess=True,
        ),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if macro_result.returncode != 0:
        diagnostic = next((line.strip() for line in macro_result.stderr.splitlines() if line.strip()), "compiler produced no diagnostic")
        return ("failed", diagnostic, [])
    return (
        "ok",
        "compiler AST and preprocessor declaration-form records",
        canonical_facts(
            [
                *discover_ast_facts(
                    ast,
                    header_root,
                    header,
                    (
                        (header_root, "public"),
                        (resource_include, "compiler-resource"),
                        (linux_uapi_include, "linux-uapi"),
                    ),
                ),
                *discover_macro_facts(macro_result.stdout, header_root),
            ]
        ),
    )


def collect_tree(
    *,
    tree: str,
    compiler: str,
    profiles: Sequence[callable_inventory.Profile],
    headers: Sequence[str],
    header_root: Path,
    resource_include: Path,
    linux_uapi_include: Path,
    oracle_not_applicable: Mapping[tuple[str, str], str],
) -> dict[tuple[str, str], dict[str, Any]]:
    results: dict[tuple[str, str], dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="crabc-x86-header-abi-matrix.") as temporary:
        work_dir = Path(temporary)
        for profile in profiles:
            for header in headers:
                key = (header, profile.identifier)
                if tree == "reference" and not (header_root / header).is_file():
                    results[key] = {
                        "detail": "header is a project-only extension and has no pinned-musl pathname",
                        "facts": [],
                        "status": "not-in-pinned-inventory",
                    }
                    continue
                status, detail, facts = compiler_profile(
                    compiler=compiler,
                    profile=profile,
                    header=header,
                    header_root=header_root,
                    resource_include=resource_include,
                    linux_uapi_include=linux_uapi_include,
                    work_dir=work_dir,
                )
                if status == "failed" and tree == "reference" and key in oracle_not_applicable:
                    status = "oracle-not-applicable"
                    detail = oracle_not_applicable[key]
                results[key] = {"detail": detail, "facts": facts, "status": status}
    return results


def build_report(
    *,
    compiler: str,
    project_include: Path,
    musl_include: Path,
    linux_uapi_include: Path,
    contract: MatrixContract | None = None,
) -> dict[str, Any]:
    """Compile the finite profile cross-product and return its canonical report."""
    contract = load_contract() if contract is None else contract
    require(project_include.is_dir() and not project_include.is_symlink(), "project include root is unsafe")
    callable_inventory.require_pinned_musl_include(musl_include)
    callable_inventory.require_pinned_linux_uapi_include(linux_uapi_include)
    pinned_headers = callable_inventory.load_headers(contract.public_headers)
    require(callable_inventory.public_header_paths(musl_include) == pinned_headers, "pinned musl public header tree drifted")
    candidate_headers = callable_inventory.candidate_header_paths(project_include, pinned_headers)
    resource_include = callable_inventory.compiler_resource_include(compiler)
    candidate = collect_tree(
        tree="candidate",
        compiler=compiler,
        profiles=contract.profiles,
        headers=candidate_headers,
        header_root=project_include,
        resource_include=resource_include,
        linux_uapi_include=linux_uapi_include,
        oracle_not_applicable=contract.oracle_not_applicable,
    )
    reference = collect_tree(
        tree="reference",
        compiler=compiler,
        profiles=contract.profiles,
        headers=pinned_headers,
        header_root=musl_include,
        resource_include=resource_include,
        linux_uapi_include=linux_uapi_include,
        oracle_not_applicable=contract.oracle_not_applicable,
    )

    rows: list[dict[str, Any]] = []
    for header in candidate_headers:
        for profile in contract.profiles:
            key = (header, profile.identifier)
            candidate_result = candidate[key]
            require(candidate_result["status"] == "ok", f"candidate ABI matrix row failed: {header}:{profile.identifier}: {candidate_result['detail']}")
            candidate_facts = candidate_result["facts"]
            row: dict[str, Any] = {
                "candidate": facts_summary(candidate_facts),
                "candidate_status": candidate_result["status"],
                "header": header,
                "profile": profile.identifier,
            }
            if header not in pinned_headers:
                row.update(
                    {
                        "comparison": "candidate-only-pending-c-abi-policy",
                        "reference": None,
                        "reference_status": "not-in-pinned-inventory",
                    }
                )
            else:
                reference_result = reference[key]
                row["reference_status"] = reference_result["status"]
                if reference_result["status"] == "oracle-not-applicable":
                    row.update(
                        {
                            "comparison": "oracle-not-applicable",
                            "reference": None,
                        }
                    )
                else:
                    require(reference_result["status"] == "ok", f"reference ABI matrix row failed: {header}:{profile.identifier}: {reference_result['detail']}")
                    comparison = compare_facts(candidate_facts, reference_result["facts"])
                    row.update(
                        {
                            "comparison": "matched"
                            if not comparison["candidate_only"]
                            and not comparison["reference_only"]
                            and not comparison["incompatible"]
                            else "mismatch",
                            "difference": comparison,
                            "reference": facts_summary(reference_result["facts"]),
                        }
                    )
            rows.append(row)

    comparison_counts = Counter(row["comparison"] for row in rows)
    mismatch_rows = [row for row in rows if row["comparison"] == "mismatch"]
    mismatch_fact_counts = Counter()
    for row in mismatch_rows:
        difference = row["difference"]
        assert isinstance(difference, Mapping)
        for key in ("candidate_only_count", "reference_only_count", "incompatible_count"):
            mismatch_fact_counts[key] += int(difference[key])
    incomplete_reasons = [
        f"{comparison_counts.get('mismatch', 0)} comparable header/profile rows have prototype or named declaration-form differences",
        f"{comparison_counts.get('oracle-not-applicable', 0)} pinned-musl header/profile rows are oracle-not-applicable",
        f"{comparison_counts.get('candidate-only-pending-c-abi-policy', 0)} project-only header/profile rows remain pending C ABI policy",
        "record byte layouts, archive linkage, runtime behavior, family promotion, and public support remain outside this partial matrix",
    ]
    return {
        "schema": SCHEMA,
        "contract_schema": CONTRACT_SCHEMA,
        "target": TARGET,
        "platform": PLATFORM,
        "oracle": ORACLE,
        "inputs": {
            "callable_inventory_sha256": sha256_file(contract.callable_inventory),
            "header_abi_matrix_contract_sha256": sha256_file(CONTRACT_PATH),
            "public_header_inventory_sha256": sha256_file(contract.public_headers),
            "compiler": compiler,
        },
        "scope": dict(REPORT_SCOPE),
        "work_package": dict(contract.work_package),
        "profiles": [
            {
                "defines": list(profile.defines),
                "id": profile.identifier,
                "language": profile.language,
                "standard": profile.standard,
            }
            for profile in contract.profiles
        ],
        "rows": rows,
        "summary": {
            "candidate_public_header_count": len(candidate_headers),
            "comparison_counts": dict(sorted(comparison_counts.items())),
            "complete": False,
            "incomplete_reasons": incomplete_reasons,
            "mismatch_fact_counts": dict(sorted(mismatch_fact_counts.items())),
            "mismatch_row_count": len(mismatch_rows),
            "pinned_public_header_count": len(pinned_headers),
            "profile_count": len(contract.profiles),
            "row_count": len(rows),
        },
    }


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def validate_checked_report(report: Mapping[str, Any], contract: MatrixContract) -> None:
    """Reject stale or accidentally promoting checked output without compiling."""
    expected_keys = {
        "schema",
        "contract_schema",
        "target",
        "platform",
        "oracle",
        "inputs",
        "scope",
        "work_package",
        "profiles",
        "rows",
        "summary",
    }
    require(set(report) == expected_keys, "checked header ABI matrix keys changed")
    require(report["schema"] == SCHEMA, "checked header ABI matrix schema changed")
    require(report["contract_schema"] == CONTRACT_SCHEMA, "checked header ABI matrix contract schema changed")
    require(report["target"] == TARGET and report["platform"] == PLATFORM and report["oracle"] == ORACLE, "checked header ABI matrix identity changed")
    scope = report["scope"]
    require(dict(scope) == REPORT_SCOPE if isinstance(scope, Mapping) else False, "checked header ABI matrix scope drifted")
    require(report["work_package"] == dict(contract.work_package), "checked header ABI matrix work package drifted")
    profiles = report["profiles"]
    expected_profiles = [
        {
            "defines": list(profile.defines),
            "id": profile.identifier,
            "language": profile.language,
            "standard": profile.standard,
        }
        for profile in contract.profiles
    ]
    require(profiles == expected_profiles, "checked header ABI matrix profile roster changed")
    rows = report["rows"]
    require(isinstance(rows, list) and len(rows) == 1337, "checked header ABI matrix row count changed")
    pinned_headers = callable_inventory.load_headers(contract.public_headers)
    candidate_headers = callable_inventory.candidate_header_paths(ROOT / "include", pinned_headers)
    expected_row_order = [
        (header, profile.identifier)
        for header in candidate_headers
        for profile in contract.profiles
    ]
    observed_row_order = [(str(row.get("header", "")), str(row.get("profile", ""))) for row in rows if isinstance(row, Mapping)]
    require(observed_row_order == expected_row_order, "checked header ABI matrix row order changed")
    require(len(observed_row_order) == len(rows), "checked header ABI matrix contains a non-table row")
    comparison_counts = Counter()
    mismatch_fact_counts = Counter()
    observed_oracle_not_applicable: set[tuple[str, str]] = set()
    for row in rows:
        assert isinstance(row, Mapping)
        header = row["header"]
        profile = row["profile"]
        require(row.get("candidate_status") == "ok", f"checked header ABI matrix candidate row is not usable: {header}:{profile}")
        comparison = row.get("comparison")
        require(isinstance(comparison, str), f"checked header ABI matrix comparison is invalid: {header}:{profile}")
        comparison_counts[comparison] += 1
        key = (header, profile)
        if header not in pinned_headers:
            require(
                comparison == "candidate-only-pending-c-abi-policy"
                and row.get("reference") is None
                and row.get("reference_status") == "not-in-pinned-inventory",
                f"checked header ABI matrix project-only row drifted: {header}:{profile}",
            )
            continue
        if key in contract.oracle_not_applicable:
            require(
                comparison == "oracle-not-applicable"
                and row.get("reference") is None
                and row.get("reference_status") == "oracle-not-applicable",
                f"checked header ABI matrix oracle row drifted: {header}:{profile}",
            )
            observed_oracle_not_applicable.add(key)
            continue
        require(row.get("reference_status") == "ok", f"checked header ABI matrix reference row failed: {header}:{profile}")
        require(comparison in {"matched", "mismatch"}, f"checked header ABI matrix comparison drifted: {header}:{profile}")
        difference = row.get("difference")
        require(isinstance(difference, Mapping), f"checked header ABI matrix difference is invalid: {header}:{profile}")
        require(
            set(difference)
            == {
                "candidate_only",
                "candidate_only_count",
                "incompatible",
                "incompatible_count",
                "matched_count",
                "reference_only",
                "reference_only_count",
            },
            f"checked header ABI matrix difference keys drifted: {header}:{profile}",
        )
        for name, signature_key in (
            ("candidate_only", "signature"),
            ("reference_only", "signature"),
        ):
            entries = difference[name]
            count = difference[f"{name}_count"]
            require(
                isinstance(entries, list) and isinstance(count, int) and count == len(entries),
                f"checked header ABI matrix {name} count is invalid: {header}:{profile}",
            )
            for entry in entries:
                require(
                    isinstance(entry, Mapping)
                    and set(entry) == {"kind", "name", signature_key}
                    and all(isinstance(entry[key], str) and entry[key] for key in entry),
                    f"checked header ABI matrix {name} is not reviewable: {header}:{profile}",
                )
        incompatible_entries = difference["incompatible"]
        incompatible_count = difference["incompatible_count"]
        require(
            isinstance(incompatible_entries, list)
            and isinstance(incompatible_count, int)
            and incompatible_count == len(incompatible_entries),
            f"checked header ABI matrix incompatible count is invalid: {header}:{profile}",
        )
        for entry in incompatible_entries:
            require(
                isinstance(entry, Mapping)
                and set(entry)
                == {"candidate_signature", "kind", "name", "reference_signature"}
                and all(isinstance(entry[key], str) and entry[key] for key in entry),
                f"checked header ABI matrix incompatible fact is not reviewable: {header}:{profile}",
            )
        matched_count = difference["matched_count"]
        require(
            isinstance(matched_count, int) and matched_count >= 0,
            f"checked header ABI matrix matched count is invalid: {header}:{profile}",
        )
        if comparison == "matched":
            require(
                difference["candidate_only_count"] == 0
                and difference["reference_only_count"] == 0
                and incompatible_count == 0,
                f"checked header ABI matrix matched row has differences: {header}:{profile}",
            )
        else:
            for name in ("candidate_only_count", "reference_only_count", "incompatible_count"):
                count = difference.get(name)
                require(isinstance(count, int) and count >= 0, f"checked header ABI matrix {name} is invalid: {header}:{profile}")
                mismatch_fact_counts[name] += count
    require(
        observed_oracle_not_applicable == set(contract.oracle_not_applicable),
        "checked header ABI matrix oracle exception coverage drifted",
    )
    summary = report["summary"]
    require(isinstance(summary, Mapping), "checked header ABI matrix summary is invalid")
    require(
        summary.get("candidate_public_header_count") == len(candidate_headers)
        and summary.get("pinned_public_header_count") == len(pinned_headers)
        and summary.get("profile_count") == len(contract.profiles)
        and summary.get("row_count") == len(rows),
        "checked header ABI matrix summary dimensions changed",
    )
    require(summary.get("comparison_counts") == dict(sorted(comparison_counts.items())), "checked header ABI matrix comparison summary changed")
    require(summary.get("mismatch_fact_counts") == dict(sorted(mismatch_fact_counts.items())), "checked header ABI matrix fact summary changed")
    require(summary.get("mismatch_row_count") == comparison_counts["mismatch"], "checked header ABI matrix mismatch row count changed")
    require(summary.get("complete") is False, "header ABI matrix must remain a partial report")
    inputs = report["inputs"]
    require(isinstance(inputs, Mapping), "checked header ABI matrix inputs are invalid")
    require(
        dict(inputs)
        == {
            "callable_inventory_sha256": sha256_file(contract.callable_inventory),
            "header_abi_matrix_contract_sha256": sha256_file(CONTRACT_PATH),
            "public_header_inventory_sha256": sha256_file(contract.public_headers),
            "compiler": "clang",
        },
        "checked header ABI matrix inputs drifted",
    )


def check_output(path: Path, rendered: str) -> None:
    try:
        existing = path.read_text(encoding="utf-8")
    except OSError as error:
        raise HeaderAbiMatrixError(f"checked header ABI report is missing: {path.relative_to(ROOT)} ({error})") from error
    require(existing == rendered, f"checked header ABI report is stale: regenerate {path.relative_to(ROOT)} with --write")


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", default="clang")
    parser.add_argument("--project-include", type=Path, default=ROOT / "include")
    parser.add_argument("--musl-include", type=Path, default=Path("/opt/musl-1.2.6/include"))
    parser.add_argument("--linux-uapi-include", type=Path, default=Path("/opt/linux-5.10-uapi/include"))
    parser.add_argument("--write", action="store_true", help="update the checked report")
    parser.add_argument("--check", action="store_true", help="require the checked report to match compiler output")
    parsed = parser.parse_args(arguments)
    require(not (parsed.write and parsed.check), "--write and --check cannot be combined")
    contract = load_contract()
    report = build_report(
        compiler=parsed.compiler,
        project_include=parsed.project_include,
        musl_include=parsed.musl_include,
        linux_uapi_include=parsed.linux_uapi_include,
        contract=contract,
    )
    rendered = canonical_json(report)
    if parsed.write:
        require(not contract.generated_report.is_symlink(), "checked header ABI report path is a symlink")
        contract.generated_report.parent.mkdir(parents=True, exist_ok=True)
        contract.generated_report.write_text(rendered, encoding="utf-8")
    elif parsed.check:
        check_output(contract.generated_report, rendered)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HeaderAbiMatrixError as error:
        raise SystemExit(f"x86 header ABI matrix: ERROR: {error}") from error
