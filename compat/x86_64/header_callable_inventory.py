#!/usr/bin/env python3
"""Generate the canonical x86 public-header callable inventory.

This is deliberately a compiler-front-end inventory, not a regular-expression
scan of C headers.  For every fixed feature/language profile it invokes Clang
against the isolated pinned-musl and project header roots, consumes Clang's
JSON AST for function declarations, and consumes its preprocessor record for
callable macros.  The checked JSON has no machine-local paths or timestamps.

The resulting inventory is an accounting input to, rather than evidence of,
``libc.headers-layouts`` completion.  In particular, a nonempty static export
complement makes the inventory explicitly incomplete; it cannot silently
promote a header or runtime family.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "header_callable_inventory.toml"
SCHEMA = "crabc.x86_64-header-callable-inventory-report/v1"
TARGET = "x86_64-unknown-linux-musl"
PLATFORM = "Linux/x86-64 little-endian"
MUSL_VERSION = "1.2.6"
MUSL_SOURCE_SHA256 = "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a"
LINUX_UAPI_VERSION = "5.10"
LINUX_UAPI_SOURCE_SHA256 = "dcdf99e43e98330d925016985bfbc7b83c66d367b714b2de0cbbfcbf83d8ca43"
LINUX_UAPI_HEADER_MANIFEST_SHA256 = "00cdc98ceb35926f68dc57dc0d84a989a6df4f60f84b1ae5981b54bb1088eb0e"


class InventoryError(ValueError):
    """The callable inventory contract cannot be evaluated safely."""


@dataclass(frozen=True)
class Profile:
    identifier: str
    language: str
    standard: str
    defines: tuple[str, ...]


@dataclass(frozen=True)
class InventoryContract:
    public_headers: Path
    static_exports: Path
    generated_inventory: Path
    pinned_public_header_count: int
    candidate_public_header_count: int
    profiles: tuple[Profile, ...]
    oracle_not_applicable: Mapping[tuple[str, str], str]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InventoryError(message)


def relative_project_path(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty path")
    path = Path(value)
    require(not path.is_absolute() and ".." not in path.parts, f"{location} escapes the repository")
    result = ROOT / path
    require(result.is_file(), f"{location} does not name a regular repository file: {value}")
    return result


def relative_project_destination(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty path")
    path = Path(value)
    require(not path.is_absolute() and ".." not in path.parts, f"{location} escapes the repository")
    parent = ROOT / path.parent
    require(parent.is_dir() and not parent.is_symlink(), f"{location} parent is unsafe: {path.parent}")
    return ROOT / path


def load_contract(path: Path = CONTRACT_PATH) -> InventoryContract:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InventoryError(f"cannot load {path.relative_to(ROOT)}: {error}") from error

    require(raw.get("schema") == "crabc.x86_64-header-callable-inventory/v1", "inventory contract schema changed")
    require(raw.get("target") == TARGET, "inventory contract target changed")
    require(raw.get("platform") == PLATFORM, "inventory contract platform changed")
    require(raw.get("oracle") == "Pinned musl 1.2.6", "inventory contract oracle changed")

    inputs = raw.get("inputs")
    require(isinstance(inputs, Mapping), "inventory contract inputs are missing")
    require(inputs.get("musl_version") == MUSL_VERSION, "inventory contract musl version changed")
    require(inputs.get("musl_source_sha256") == MUSL_SOURCE_SHA256, "inventory contract musl pin changed")
    require(inputs.get("linux_uapi_version") == LINUX_UAPI_VERSION, "inventory contract Linux UAPI version changed")
    require(inputs.get("linux_uapi_source_sha256") == LINUX_UAPI_SOURCE_SHA256, "inventory contract Linux UAPI pin changed")
    require(
        inputs.get("linux_uapi_header_manifest_sha256") == LINUX_UAPI_HEADER_MANIFEST_SHA256,
        "inventory contract Linux UAPI export manifest changed",
    )

    policy = raw.get("policy")
    require(
        policy
        == {
            "compiler_ast_json": True,
            "compiler_preprocessor_records": True,
            "header_text_parsing": False,
            "candidate_headers_first": True,
            "native_execution_only": True,
            "archive_extraction_required_for_external": True,
            "family_promotion": False,
            "public_support": False,
        },
        "inventory policy changed",
    )

    raw_profiles = raw.get("profile")
    require(isinstance(raw_profiles, list) and raw_profiles, "inventory profiles are missing")
    profiles: list[Profile] = []
    seen_profiles: set[str] = set()
    for index, item in enumerate(raw_profiles):
        require(isinstance(item, Mapping), f"profile[{index}] is invalid")
        identifier = item.get("id")
        language = item.get("language")
        standard = item.get("standard")
        defines = item.get("defines")
        require(isinstance(identifier, str) and identifier, f"profile[{index}].id is invalid")
        require(identifier not in seen_profiles, f"profile {identifier} is duplicated")
        seen_profiles.add(identifier)
        require(language in {"c", "cxx"}, f"profile {identifier} has an unsupported language")
        require(isinstance(standard, str) and standard, f"profile {identifier}.standard is invalid")
        require(isinstance(defines, list), f"profile {identifier}.defines is invalid")
        checked_defines: list[str] = []
        for define in defines:
            require(isinstance(define, str) and define and "\n" not in define, f"profile {identifier} has an invalid define")
            checked_defines.append(define)
        require(len(checked_defines) == len(set(checked_defines)), f"profile {identifier} repeats a define")
        profiles.append(Profile(identifier, language, standard, tuple(checked_defines)))

    expected_profiles = (
        "c11-gnu",
        "cxx17-gnu",
        "c11-strict",
        "c11-posix-2008",
        "c11-xopen-700",
        "c11-bsd",
        "cxx17-strict",
    )
    require(tuple(profile.identifier for profile in profiles) == expected_profiles, "inventory profile order changed")

    raw_na = raw.get("oracle_not_applicable")
    require(isinstance(raw_na, list), "inventory oracle-not-applicable rows are missing")
    oracle_not_applicable: dict[tuple[str, str], str] = {}
    for index, item in enumerate(raw_na):
        require(isinstance(item, Mapping), f"oracle_not_applicable[{index}] is invalid")
        header = item.get("header")
        profile = item.get("profile")
        reason = item.get("reason")
        require(isinstance(header, str) and header, f"oracle_not_applicable[{index}].header is invalid")
        require(isinstance(profile, str) and profile in seen_profiles, f"oracle_not_applicable[{index}].profile is invalid")
        require(isinstance(reason, str) and reason, f"oracle_not_applicable[{index}].reason is invalid")
        key = (header, profile)
        require(key not in oracle_not_applicable, f"oracle-not-applicable row {header}:{profile} is duplicated")
        oracle_not_applicable[key] = reason
    require(
        set(oracle_not_applicable) == {("aio.h", "c11-strict"), ("aio.h", "cxx17-strict")},
        "inventory oracle-not-applicable rows changed",
    )

    pinned_count = raw.get("pinned_public_header_count")
    candidate_count = raw.get("candidate_public_header_count")
    require(pinned_count == 183, "inventory pinned public header count changed")
    require(candidate_count == 191, "inventory candidate public header count changed")

    return InventoryContract(
        public_headers=relative_project_path(raw.get("public_headers"), "public_headers"),
        static_exports=relative_project_path(raw.get("static_c_abi_exports"), "static_c_abi_exports"),
        generated_inventory=relative_project_destination(raw.get("generated_inventory"), "generated_inventory"),
        pinned_public_header_count=pinned_count,
        candidate_public_header_count=candidate_count,
        profiles=tuple(profiles),
        oracle_not_applicable=oracle_not_applicable,
    )


def load_headers(path: Path) -> list[str]:
    try:
        values = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise InventoryError(f"cannot read public header inventory: {error}") from error
    headers: list[str] = []
    for line_number, value in enumerate(values, start=1):
        require(value and not value.startswith("#"), f"public header inventory line {line_number} is invalid")
        relative = Path(value)
        require(not relative.is_absolute() and ".." not in relative.parts, f"public header inventory path escapes root: {value}")
        require(value == relative.as_posix(), f"public header inventory path is not canonical: {value}")
        headers.append(value)
    require(headers == sorted(headers), "public header inventory is not ASCII sorted")
    require(len(headers) == len(set(headers)), "public header inventory contains duplicates")
    require(len(headers) == 183, "pinned public header inventory count changed")
    return headers


def public_header_paths(header_root: Path) -> list[str]:
    paths: list[str] = []
    for path in header_root.rglob("*.h"):
        require(path.is_file() and not path.is_symlink(), f"public header is unsafe: {path}")
        relative = path.relative_to(header_root)
        # Match the established public-header closure boundary: `bits/` is
        # a private implementation namespace reached through public roots,
        # never a public pathname in its own right.
        if relative.parts[0] == "bits":
            continue
        paths.append(relative.as_posix())
    paths.sort()
    require(len(paths) == len(set(paths)), "candidate public header paths are duplicated")
    return paths


def candidate_header_paths(project_include: Path, pinned_headers: Sequence[str]) -> list[str]:
    paths = public_header_paths(project_include)
    require(len(paths) == 191, "candidate public header count changed")
    require(set(pinned_headers).issubset(paths), "candidate public header tree omits a pinned public header")
    return paths


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def load_static_exports(path: Path) -> list[str]:
    try:
        values = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise InventoryError(f"cannot read static export ratchet: {error}") from error
    exports = [value.strip() for value in values if value.strip() and not value.startswith("#")]
    require(len(exports) == len(set(exports)), "static export ratchet contains duplicates")
    # The ratchet is an independent historical artifact whose comments claim
    # ASCII ordering but whose current authoritative contents are not fully
    # ordered.  Treat it as an exact input (its complete-file digest is in the
    # report) and canonicalize only this generated view.
    return sorted(exports)


def require_pinned_musl_include(path: Path) -> None:
    require(path.is_dir() and not path.is_symlink(), f"pinned musl include root is unsafe: {path}")
    marker = path.parent / ".crabc-oracle"
    require(marker.is_file() and not marker.is_symlink(), f"pinned musl provenance marker is missing: {marker}")
    expected = {
        "format": "crabc-pinned-musl-oracle-v1",
        "version": MUSL_VERSION,
        "source_sha256": MUSL_SOURCE_SHA256,
        "fallback_revision": "9fa28ece75d8a2191de7c5bb53bed224c5947417",
        "architecture": "x86_64",
    }
    observed: dict[str, str] = {}
    for line in marker.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        require(separator and key and value, "pinned musl provenance marker is malformed")
        observed[key] = value
    require(observed == expected, "pinned musl provenance marker does not match the frozen x86 input")


def require_pinned_linux_uapi_include(path: Path) -> None:
    require(path.is_dir() and not path.is_symlink(), f"Linux UAPI include root is unsafe: {path}")
    marker = path.parent / ".crabc-linux-uapi"
    require(marker.is_file() and not marker.is_symlink(), f"Linux UAPI provenance marker is missing: {marker}")
    expected = {
        "format": "crabc-linux-uapi-v1",
        "version": LINUX_UAPI_VERSION,
        "source_sha256": LINUX_UAPI_SOURCE_SHA256,
        "architecture": "x86_64",
        "install_arch": "x86",
        "header_count": "935",
        "header_manifest_sha256": LINUX_UAPI_HEADER_MANIFEST_SHA256,
    }
    observed: dict[str, str] = {}
    for line in marker.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        require(separator and key and value, "Linux UAPI provenance marker is malformed")
        observed[key] = value
    require(observed == expected, "Linux UAPI provenance marker does not match the frozen x86 input")
    for required in ("linux/kd.h", "linux/soundcard.h", "linux/vt.h"):
        require((path / required).is_file(), f"pinned Linux UAPI export lacks {required}")


def compiler_resource_include(compiler: str) -> Path:
    result = subprocess.run(
        [compiler, "-print-resource-dir"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    require(result.returncode == 0, f"compiler does not report a resource directory: {result.stderr.strip()}")
    path = Path(result.stdout.strip()) / "include"
    require(path.is_dir(), f"compiler resource include directory is missing: {path}")
    return path


def compiler_command(
    compiler: str,
    profile: Profile,
    header_root: Path,
    resource_include: Path,
    linux_uapi_include: Path,
    source: Path,
    *,
    ast: bool,
    preprocess: bool,
) -> list[str]:
    require(ast != preprocess, "compiler invocation must select exactly one record mode")
    command = [compiler, "-x", "c" if profile.language == "c" else "c++", f"-std={profile.standard}"]
    if profile.language == "cxx":
        command.append("-nostdinc++")
    command.extend(["-nostdinc", "-I", str(header_root), "-isystem", str(resource_include), "-isystem", str(linux_uapi_include)])
    command.extend(f"-D{define}" for define in profile.defines)
    if ast:
        command.extend(["-Xclang", "-ast-dump=json", "-fsyntax-only"])
    if preprocess:
        command.extend(["-E", "-dD"])
    command.append(str(source))
    return command


def source_path_for_location(value: object, root: Path) -> str | None:
    if not isinstance(value, Mapping):
        return None
    candidates: list[object] = [value]
    for key in ("spellingLoc", "expansionLoc", "includedFrom"):
        nested = value.get(key)
        if isinstance(nested, Mapping):
            candidates.append(nested)
    resolved_root = root.resolve()
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        file_name = candidate.get("file")
        if not isinstance(file_name, str) or not file_name or file_name.startswith("<"):
            continue
        try:
            candidate_path = Path(file_name).resolve()
            return candidate_path.relative_to(resolved_root).as_posix()
        except (OSError, ValueError):
            continue
    return None


def source_line_for_location(value: object) -> int | None:
    if not isinstance(value, Mapping):
        return None
    line = value.get("line")
    return line if isinstance(line, int) and line > 0 else None


def has_function_body(node: Mapping[str, Any]) -> bool:
    return any(isinstance(child, Mapping) and child.get("kind") == "CompoundStmt" for child in node.get("inner", []))


def function_classification(node: Mapping[str, Any]) -> str:
    storage = node.get("storageClass")
    inline = node.get("inline") is True
    # A header-local static definition cannot require an archive member.  An
    # external `inline` declaration can still require an out-of-line C
    # definition, so it remains deliberately conservative and external.
    if storage == "static" and inline and has_function_body(node):
        return "inline"
    return "external"


def discover_functions(
    ast: Mapping[str, Any], header_root: Path, primary_header: str | None = None
) -> list[dict[str, Any]]:
    """Return declarations physically emitted from one compiler header root."""
    records: list[dict[str, Any]] = []
    stack: list[Mapping[str, Any]] = [ast]
    while stack:
        node = stack.pop()
        inner = node.get("inner", [])
        if isinstance(inner, list):
            stack.extend(child for child in reversed(inner) if isinstance(child, Mapping))
        if node.get("kind") != "FunctionDecl":
            continue
        name = node.get("name")
        type_info = node.get("type")
        if not isinstance(name, str) or not name or not isinstance(type_info, Mapping):
            continue
        qualified_type = type_info.get("qualType")
        if not isinstance(qualified_type, str) or not qualified_type:
            continue
        location = node.get("loc")
        declaring_header = source_path_for_location(location, header_root)
        origin_resolution = "physical"
        if declaring_header is None and primary_header is not None:
            # Clang's compact JSON AST omits a repeated `file` key when the
            # declaration has the same presumed source as the immediately
            # preceding emitted declaration.  The direct include is still a
            # compiler-established public provenance boundary, so preserve it
            # explicitly instead of dropping the declaration.
            declaring_header = primary_header
            origin_resolution = "primary-include-fallback"
        if declaring_header is None:
            continue
        record = {
            "classification": function_classification(node),
            "declaration_kind": "function",
            "declaring_header": declaring_header,
            "line": source_line_for_location(location),
            "name": name,
            "origin_resolution": origin_resolution,
            "storage_class": node.get("storageClass") if isinstance(node.get("storageClass"), str) else "extern",
            "type": qualified_type,
        }
        records.append(record)
    return records


def preprocessor_marker_path(line: str) -> str | None:
    """Read a compiler-emitted line marker, never a source header line."""
    if not line.startswith("#"):
        return None
    try:
        fields = shlex.split(line[1:].strip())
    except ValueError:
        return None
    if len(fields) < 2 or not fields[0].isdigit():
        return None
    return fields[1]


def preprocessor_macro(line: str) -> tuple[str, str, str] | None:
    """Read a normalized `-E -dD` definition record from the compiler."""
    prefix = "#define "
    if not line.startswith(prefix):
        return None
    definition = line[len(prefix) :]
    if not definition:
        return None
    index = 0
    while index < len(definition) and (definition[index].isalnum() or definition[index] == "_"):
        index += 1
    name = definition[:index]
    if not name:
        return None
    function_like = index < len(definition) and definition[index] == "("
    replacement = definition[index:]
    if function_like:
        return (name, "function-like", replacement)
    if "__builtin_" in replacement:
        return (name, "object-like-builtin", replacement)
    return None


def discover_macros(preprocessed: str, header_root: Path) -> list[dict[str, Any]]:
    """Return callable macro records from compiler preprocessor provenance."""
    current_path: Path | None = None
    current_line: int | None = None
    records: list[dict[str, Any]] = []
    resolved_root = header_root.resolve()
    for raw_line in preprocessed.splitlines():
        marker = preprocessor_marker_path(raw_line)
        if marker is not None:
            current_path = None
            current_line = None
            if not marker.startswith("<"):
                try:
                    current_path = Path(marker).resolve()
                    current_path.relative_to(resolved_root)
                except (OSError, ValueError):
                    current_path = None
            fields = raw_line[1:].strip().split(maxsplit=1)
            if fields and fields[0].isdigit():
                current_line = int(fields[0])
            continue
        macro = preprocessor_macro(raw_line)
        if macro is not None and current_path is not None:
            name, macro_form, replacement = macro
            records.append(
                {
                    "classification": "macro",
                    "declaration_kind": "macro",
                    "declaring_header": current_path.relative_to(resolved_root).as_posix(),
                    "line": current_line,
                    "macro_form": macro_form,
                    "name": name,
                    "replacement_sha256": hashlib.sha256(replacement.encode("utf-8")).hexdigest(),
                }
            )
        if current_line is not None:
            current_line += 1
    return records


def record_key(record: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    # One declaration can be visible through many public direct includes.  It
    # remains one callable row per profile/type/classification; the source
    # provenance and every direct visibility path are accumulated below.
    return tuple(
        sorted(
            (key, str(value))
            for key, value in record.items()
            if key not in {"visible_from_headers", "declaring_header", "line", "origin_resolution"}
        )
    )


def run_header_profile(
    *,
    compiler: str,
    profile: Profile,
    header: str,
    header_root: Path,
    resource_include: Path,
    linux_uapi_include: Path,
    work_dir: Path,
) -> tuple[str, str, list[dict[str, Any]]]:
    source = work_dir / ("probe.cpp" if profile.language == "cxx" else "probe.c")
    source.write_text(f"#include <{header}>\n", encoding="utf-8")
    ast_result = subprocess.run(
        compiler_command(
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
        raise InventoryError(f"compiler did not emit JSON AST for {header}:{profile.identifier}: {error}") from error
    require(isinstance(ast, Mapping), f"compiler AST root is invalid for {header}:{profile.identifier}")

    macro_result = subprocess.run(
        compiler_command(
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
        "compiler AST and preprocessor records",
        [*discover_functions(ast, header_root, header), *discover_macros(macro_result.stdout, header_root)],
    )


def collect_tree(
    *,
    tree: str,
    compiler: str,
    profiles: Sequence[Profile],
    headers: Sequence[str],
    header_root: Path,
    resource_include: Path,
    linux_uapi_include: Path,
    oracle_not_applicable: Mapping[tuple[str, str], str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: dict[tuple[tuple[str, str], ...], dict[str, Any]] = {}
    runs: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="crabc-x86-header-callable-inventory.") as temporary:
        work_dir = Path(temporary)
        for profile in profiles:
            for header in headers:
                if tree == "reference" and not (header_root / header).is_file():
                    runs.append(
                        {
                            "detail": "header is a project-only extension and has no pinned-musl pathname",
                            "header": header,
                            "profile": profile.identifier,
                            "status": "not-in-pinned-inventory",
                            "tree": tree,
                        }
                    )
                    continue
                status, detail, observed = run_header_profile(
                    compiler=compiler,
                    profile=profile,
                    header=header,
                    header_root=header_root,
                    resource_include=resource_include,
                    linux_uapi_include=linux_uapi_include,
                    work_dir=work_dir,
                )
                run_status = status
                if status == "failed" and tree == "reference" and (header, profile.identifier) in oracle_not_applicable:
                    run_status = "oracle-not-applicable"
                    detail = oracle_not_applicable[(header, profile.identifier)]
                runs.append(
                    {
                        "detail": detail,
                        "header": header,
                        "profile": profile.identifier,
                        "status": run_status,
                        "tree": tree,
                    }
                )
                if run_status != "ok":
                    continue
                for observed_record in observed:
                    record = {
                        **observed_record,
                        "profile": profile.identifier,
                        "tree": tree,
                        "visible_from_headers": [header],
                    }
                    key = record_key(record)
                    prior = records.get(key)
                    if prior is None:
                        records[key] = record
                    else:
                        prior["visible_from_headers"] = sorted(set(prior["visible_from_headers"]) | {header})
                        # Prefer a physical compiler location to the compact
                        # AST's direct-include fallback.  If both are equally
                        # physical, retain the lexical minimum so reordering
                        # independent compiler work cannot perturb JSON.
                        prior_location = (
                            str(prior.get("origin_resolution", "")),
                            str(prior.get("declaring_header", "")),
                            str(prior.get("line", "")),
                        )
                        observed_location = (
                            str(record.get("origin_resolution", "")),
                            str(record.get("declaring_header", "")),
                            str(record.get("line", "")),
                        )
                        if observed_location < prior_location:
                            for field in ("declaring_header", "line", "origin_resolution"):
                                prior[field] = record.get(field)
    return (list(records.values()), runs)


def missing_candidate_records(reference_records: Iterable[Mapping[str, Any]], candidate_records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    candidate_names = {
        (str(record["profile"]), str(record["name"]))
        for record in candidate_records
        if record.get("classification") in {"external", "inline", "macro"}
    }
    missing: list[dict[str, Any]] = []
    for record in reference_records:
        name = record.get("name")
        profile = record.get("profile")
        classification = record.get("classification")
        if not isinstance(name, str) or not isinstance(profile, str) or classification not in {"external", "inline", "macro"}:
            continue
        if (profile, name) in candidate_names:
            continue
        missing.append(
            {
                "classification": "missing",
                "declaration_kind": record.get("declaration_kind"),
                "declaring_header": record.get("declaring_header"),
                "line": record.get("line"),
                "name": name,
                "profile": profile,
                "reference_classification": classification,
                "tree": "comparison",
                "visible_from_headers": record.get("visible_from_headers", []),
            }
        )
    return missing


def canonical_records(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for record in records:
        value = dict(record)
        headers = value.get("visible_from_headers")
        if isinstance(headers, list):
            value["visible_from_headers"] = sorted(set(str(header) for header in headers))
        normalized.append(value)
    return sorted(
        normalized,
        key=lambda record: (
            str(record.get("tree", "")),
            str(record.get("profile", "")),
            str(record.get("classification", "")),
            str(record.get("name", "")),
            str(record.get("declaration_kind", "")),
            str(record.get("declaring_header", "")),
            str(record.get("line", "")),
            str(record.get("type", "")),
        ),
    )


def build_report(
    *,
    compiler: str,
    project_include: Path,
    musl_include: Path,
    linux_uapi_include: Path,
    contract: InventoryContract | None = None,
) -> dict[str, Any]:
    contract = load_contract() if contract is None else contract
    require(project_include.is_dir() and not project_include.is_symlink(), f"project include root is unsafe: {project_include}")
    require_pinned_musl_include(musl_include)
    require_pinned_linux_uapi_include(linux_uapi_include)
    pinned_headers = load_headers(contract.public_headers)
    require(contract.pinned_public_header_count == len(pinned_headers), "pinned public header count contract changed")
    require(
        public_header_paths(musl_include) == pinned_headers,
        "pinned musl public header tree drifted from the frozen public-header inventory",
    )
    candidate_headers = candidate_header_paths(project_include, pinned_headers)
    require(contract.candidate_public_header_count == len(candidate_headers), "candidate public header count contract changed")
    for header in candidate_headers:
        require((project_include / header).is_file(), f"project include root lacks listed public header {header}")
    exports = load_static_exports(contract.static_exports)
    resource_include = compiler_resource_include(compiler)

    candidate_records, candidate_runs = collect_tree(
        tree="candidate",
        compiler=compiler,
        profiles=contract.profiles,
        headers=candidate_headers,
        header_root=project_include,
        resource_include=resource_include,
        linux_uapi_include=linux_uapi_include,
        oracle_not_applicable=contract.oracle_not_applicable,
    )
    reference_records, reference_runs = collect_tree(
        tree="reference",
        compiler=compiler,
        profiles=contract.profiles,
        headers=pinned_headers,
        header_root=musl_include,
        resource_include=resource_include,
        linux_uapi_include=linux_uapi_include,
        oracle_not_applicable=contract.oracle_not_applicable,
    )
    records = canonical_records([*candidate_records, *reference_records, *missing_candidate_records(reference_records, candidate_records)])
    profile_runs = sorted(
        [*candidate_runs, *reference_runs],
        key=lambda record: (record["tree"], record["profile"], record["header"]),
    )

    candidate_external = sorted(
        {
            str(record["name"])
            for record in records
            if record.get("tree") == "candidate" and record.get("classification") == "external"
        }
    )
    static_export_set = set(exports)
    complement = sorted(set(candidate_external) - static_export_set)
    record_counts = Counter(str(record.get("classification")) for record in records)
    run_counts = Counter(str(record.get("status")) for record in profile_runs)
    incomplete_reasons: list[str] = []
    if run_counts.get("failed", 0):
        incomplete_reasons.append("one or more declared profile/header compiler records failed")
    if record_counts.get("missing", 0):
        incomplete_reasons.append("one or more pinned-musl callable names are absent from the candidate inventory")
    if complement:
        incomplete_reasons.append("candidate external callable names are absent from the static export ratchet")

    return {
        "schema": SCHEMA,
        "contract_schema": "crabc.x86_64-header-callable-inventory/v1",
        "target": TARGET,
        "platform": PLATFORM,
        "oracle": "Pinned musl 1.2.6",
        "inputs": {
            "compiler": "clang JSON AST and preprocessor records",
            "header_inventory_sha256": sha256_file(contract.public_headers),
            "linux_uapi_header_manifest_sha256": LINUX_UAPI_HEADER_MANIFEST_SHA256,
            "linux_uapi_source_sha256": LINUX_UAPI_SOURCE_SHA256,
            "linux_uapi_version": LINUX_UAPI_VERSION,
            "musl_source_sha256": MUSL_SOURCE_SHA256,
            "musl_version": MUSL_VERSION,
            "static_c_abi_exports_sha256": sha256_file(contract.static_exports),
        },
        "scope": {
            "archive_extraction_required_for_external": True,
            "family_promotion": False,
            "header_text_parsing": False,
            "public_support": False,
        },
        "profiles": [
            {
                "defines": list(profile.defines),
                "id": profile.identifier,
                "language": profile.language,
                "standard": profile.standard,
            }
            for profile in contract.profiles
        ],
        "profile_runs": profile_runs,
        "callables": records,
        "static_export_complement": {
            "kind": "candidate-external-callables-absent-from-static-c-abi-export-ratchet",
            "members": complement,
        },
        "summary": {
            "callable_classification_counts": dict(sorted(record_counts.items())),
            "candidate_external_callable_count": len(candidate_external),
            "complete": not incomplete_reasons,
            "incomplete_reasons": incomplete_reasons,
            "profile_run_counts": dict(sorted(run_counts.items())),
            "candidate_public_header_count": len(candidate_headers),
            "pinned_public_header_count": len(pinned_headers),
            "static_export_complement_count": len(complement),
        },
    }


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def check_output(path: Path, rendered: str) -> None:
    try:
        existing = path.read_text(encoding="utf-8")
    except OSError as error:
        raise InventoryError(f"checked inventory is missing: {path.relative_to(ROOT)} ({error})") from error
    require(existing == rendered, f"checked inventory is stale: regenerate {path.relative_to(ROOT)} with --write")


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", default=os.environ.get("CRABC_X86_CALLABLE_CLANG", "clang"))
    parser.add_argument("--project-include", type=Path, default=ROOT / "include")
    parser.add_argument("--musl-include", type=Path, default=Path("/opt/musl-1.2.6/include"))
    parser.add_argument("--linux-uapi-include", type=Path, default=Path("/opt/linux-5.10-uapi/include"))
    parser.add_argument("--output", type=Path, help="write a generated inventory to this exact path")
    parser.add_argument("--write", action="store_true", help="update the reviewed checked inventory")
    parser.add_argument("--check", action="store_true", help="require the checked inventory to match compiler output")
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
    if parsed.output is not None:
        require(not parsed.output.is_symlink(), f"inventory output path is a symlink: {parsed.output}")
        parsed.output.write_text(rendered, encoding="utf-8")
    elif parsed.write:
        require(not contract.generated_inventory.is_symlink(), "checked inventory path is a symlink")
        contract.generated_inventory.write_text(rendered, encoding="utf-8")
    elif parsed.check:
        check_output(contract.generated_inventory, rendered)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InventoryError as error:
        raise SystemExit(f"x86 header callable inventory: ERROR: {error}") from error
