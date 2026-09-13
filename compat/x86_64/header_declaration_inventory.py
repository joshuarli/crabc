#!/usr/bin/env python3
"""Collect and replay raw native x86 public-header declaration occurrences.

This companion intentionally does not replace ``header_abi_matrix.py``.  The
matrix still emits its compact, canonical declaration forms.  This collector
keeps the raw Clang AST and preprocessor records behind that matrix boundary,
then records every header-owned function and file-scope variable occurrence
before any canonical collapse.  It also records ordered public-header macro
``#define``/``#undef`` events separately from the derived final-active view.

The report is a conservative compiler receipt.  Clang JSON does not expose a
complete language-linkage or semantic-definition model for every declaration,
so an observation that cannot be proved from the retained AST remains
``unresolved-from-json``.  Consumers must not promote such an observation into
an ABI selection conclusion.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import shlex
import subprocess
import sys
import tomllib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MODULE_DIRECTORY = ROOT / "compat" / "x86_64"
if str(MODULE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(MODULE_DIRECTORY))

import header_abi_matrix as abi_matrix
import header_callable_inventory as callable_inventory


SCHEMA = "crabc.x86_64-header-declaration-inventory/v1"
RAW_ARTIFACT_SCHEMA = "crabc.x86_64-header-declaration-inventory-raw/v1"
VALIDATION_SCHEMA = "crabc.x86_64-header-declaration-inventory-validation/v1"
TARGET = "x86_64-unknown-linux-musl"
PLATFORM = "Linux/x86-64 little-endian"
ORACLE = "Pinned musl 1.2.6"
COLLECTOR_ID = "raw-declaration-occurrences-v1"
DEFAULT_WORKERS = 4
DEFAULT_TIMEOUT_SECONDS = abi_matrix.DEFAULT_COMPILER_JOB_TIMEOUT_SECONDS
NON_FILE_SCOPE_KINDS = frozenset({
    "BlockDecl",
    "CXXConstructorDecl",
    "CXXConversionDecl",
    "CXXDestructorDecl",
    "CXXMethodDecl",
    "CXXRecordDecl",
    "ClassTemplateDecl",
    "ClassTemplateSpecializationDecl",
    "FunctionDecl",
    "RecordDecl",
})
SOURCE_CONTRACT_FILES = (
    "compat/x86_64/header_declaration_inventory.py",
    "compat/x86_64/header_abi_matrix.py",
    "compat/x86_64/header_abi_matrix.toml",
    "compat/x86_64/header_callable_inventory.py",
    "compat/x86_64/header_callable_inventory.toml",
    "compat/x86_64/header_callable_extension_contract.py",
    "compat/x86_64/header_callable_extension_contract.toml",
    "compat/x86_64/header_callable_inventory.json",
    "compat/x86_64/public_headers.txt",
)
ROOTED_DEPENDENCY_CLASSIFICATIONS = frozenset({
    "candidate-header-root",
    "compiler-resource",
    "linux-uapi",
    "pinned-musl-header-root",
})
IMAGE_ID_PATTERN = re.compile(r"crabc-core-evidence@sha256:[0-9a-f]{64}")


class HeaderDeclarationInventoryError(ValueError):
    """The raw declaration inventory cannot be collected or replayed safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HeaderDeclarationInventoryError(message)


def require_string(value: object, location: str, *, allow_empty: bool = False) -> str:
    require(isinstance(value, str) and (allow_empty or bool(value)), f"{location} must be a {'string' if allow_empty else 'nonempty string'}")
    return value


def require_integer(value: object, location: str, *, minimum: int | None = None) -> int:
    require(type(value) is int, f"{location} must be an integer")
    if minimum is not None:
        require(value >= minimum, f"{location} must be at least {minimum}")
    return value


def require_boolean(value: object, location: str) -> bool:
    require(type(value) is bool, f"{location} must be a Boolean")
    return value


def require_sha256(value: object, location: str) -> str:
    digest = require_string(value, location)
    require(
        len(digest) == 64 and all(character in "0123456789abcdef" for character in digest),
        f"{location} must be a lowercase SHA-256 digest",
    )
    return digest


def normalized_absolute_observation(value: object, location: str) -> str:
    """Accept an observed path only in one lexical absolute spelling.

    Original compiler paths are observations, never host replay inputs.  Their
    spelling still matters: otherwise a retained dependency could be assigned
    to the wrong include root while preserving its copied bytes.
    """
    rendered = require_string(value, location)
    require("\x00" not in rendered, f"{location} contains a NUL")
    path = Path(rendered)
    require(path.is_absolute(), f"{location} is not absolute")
    normalized = os.path.normpath(rendered)
    require(rendered == normalized, f"{location} is not lexically normalized")
    return rendered


def canonical_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.is_symlink(), f"output path is a symlink: {path}")
    path.write_text(canonical_json(value), encoding="utf-8")


def load_json_object(path: Path, location: str) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HeaderDeclarationInventoryError(f"cannot read {location}: {error}") from error
    require(isinstance(raw, dict), f"{location} must be a JSON object")
    return raw


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return callable_inventory.sha256_file(path)
    except OSError as error:
        raise HeaderDeclarationInventoryError(f"cannot hash {path}: {error}") from error


def regular_file_identity(path: Path, logical_path: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"regular input is unsafe: {path}")
    return {"path": logical_path, "sha256": sha256_file(path), "size": path.stat().st_size}


def snapshot_regular_file(
    output: Path,
    source: Path,
    retained_relative: str,
    original_path_observation: str,
) -> dict[str, Any]:
    """Copy one live input once and bind before/after source bytes explicitly."""
    retained = output / safe_relative_path(retained_relative, "retained input path")
    require(not retained.exists() and not retained.is_symlink(), f"retained input path is already occupied: {retained_relative}")
    before = regular_file_identity(source, original_path_observation)
    retained.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copyfile(source, retained)
    except OSError as error:
        raise HeaderDeclarationInventoryError(f"cannot retain input {source}: {error}") from error
    after = regular_file_identity(source, original_path_observation)
    require_strict_equal(before, after, f"input changed while retained: {original_path_observation}")
    retained_identity = regular_file_identity(retained, retained_relative)
    require(
        retained_identity["sha256"] == before["sha256"] and retained_identity["size"] == before["size"],
        f"retained input differs from source: {original_path_observation}",
    )
    return {"after": after, "before": before, "retained": retained_identity}


def validate_retained_snapshot(
    output: Path,
    record: object,
    location: str,
    *,
    expected_before_path: str | None = None,
    expected_retained_path: str | None = None,
) -> dict[str, Any]:
    require(isinstance(record, Mapping) and set(record) == {"after", "before", "retained"}, f"{location} snapshot keys changed")
    before = record["before"]
    after = record["after"]
    retained = record["retained"]
    for label, value in (("before", before), ("after", after), ("retained", retained)):
        require(isinstance(value, Mapping) and set(value) == {"path", "sha256", "size"}, f"{location} {label} identity is invalid")
        require_string(value.get("path"), f"{location} {label}.path")
        require_sha256(value.get("sha256"), f"{location} {label}.sha256")
        require_integer(value.get("size"), f"{location} {label}.size", minimum=0)
    if expected_before_path is not None:
        require(before["path"] == expected_before_path, f"{location} source path changed")
        require(after["path"] == expected_before_path, f"{location} after-source path changed")
    if expected_retained_path is not None:
        require(retained["path"] == expected_retained_path, f"{location} retained path changed")
    require_strict_equal(before, after, f"{location} source stability")
    retained_path = output / safe_relative_path(retained["path"], f"{location} retained path")
    try:
        observed = regular_file_identity(retained_path, retained["path"])
    except HeaderDeclarationInventoryError as error:
        raise HeaderDeclarationInventoryError(f"{location} retained bytes are unavailable: {error}") from error
    require_strict_equal(observed, retained, f"{location} retained bytes")
    require(
        retained["sha256"] == before["sha256"] and retained["size"] == before["size"],
        f"{location} retained/source identity differs",
    )
    return dict(record)


def strict_equal(observed: object, expected: object) -> bool:
    """Compare JSON values without Python's bool/int equality loophole."""
    if type(observed) is not type(expected):
        return False
    if isinstance(observed, dict):
        return set(observed) == set(expected) and all(
            strict_equal(observed[key], expected[key]) for key in observed
        )
    if isinstance(observed, list):
        return len(observed) == len(expected) and all(
            strict_equal(left, right) for left, right in zip(observed, expected)
        )
    return observed == expected


def require_strict_equal(observed: object, expected: object, location: str) -> None:
    require(strict_equal(observed, expected), f"{location} does not reproduce retained raw evidence")


def path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def require_physical_directory(path: Path, location: str) -> Path:
    require(path.is_dir() and not path.is_symlink(), f"{location} is not a physical directory: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise HeaderDeclarationInventoryError(f"cannot resolve {location}: {error}") from error
    require(resolved == path, f"{location} must not have symlinked parents: {path}")
    return resolved


def safe_relative_path(value: object, location: str) -> Path:
    rendered = require_string(value, location)
    path = Path(rendered)
    require(
        path.parts and not path.is_absolute() and "." not in path.parts and ".." not in path.parts and path.as_posix() == rendered,
        f"{location} is not a canonical relative path",
    )
    return path


def physical_output_directory(path: Path) -> Path:
    """Create one fresh evidence directory under the checkout's ignored work root."""
    path = path if path.is_absolute() else ROOT / path
    work_root = abi_matrix.physical_x86_work_directory("header-declaration-inventory")
    try:
        relative = path.relative_to(work_root)
    except ValueError as error:
        raise HeaderDeclarationInventoryError(
            f"output must be below {work_root.relative_to(ROOT)}: {path}"
        ) from error
    require(relative.parts and "." not in relative.parts and ".." not in relative.parts, "output path is unsafe")
    current = work_root
    for component in relative.parts:
        current = current / component
        if current.exists() or current.is_symlink():
            require(current.is_dir() and not current.is_symlink(), f"output path is unsafe: {current}")
        else:
            current.mkdir()
    require(not any(path.iterdir()), f"output directory must be empty: {path}")
    return require_physical_directory(path, "output directory")


def canonical_checkout_work_root() -> Path:
    """Locate the shared checkout `.work` root from either a root or linked worktree."""
    for ancestor in (ROOT, *ROOT.parents):
        candidate = ancestor / ".work" / "worktrees"
        if candidate.is_dir() and not candidate.is_symlink():
            return require_physical_directory(ancestor / ".work", "canonical checkout work root")
    raise HeaderDeclarationInventoryError("cannot locate canonical checkout .work root")


def existing_evidence_directory(report_path: Path) -> Path:
    report_path = report_path if report_path.is_absolute() else ROOT / report_path
    require(report_path.name == "report.json", "report path must name report.json")
    evidence = report_path.parent
    require_physical_directory(evidence, "evidence directory")
    work_root = canonical_checkout_work_root()
    require(path_is_within(evidence, work_root), "evidence directory escapes canonical checkout work root")
    return evidence


def profile_records(profiles: Sequence[callable_inventory.Profile]) -> list[dict[str, Any]]:
    return abi_matrix.profile_input_records(profiles)


def command_identity(compiler: str) -> tuple[dict[str, Any], Path]:
    executable = shutil.which(compiler)
    require(executable is not None, f"compiler is not on PATH: {compiler}")
    compiler_path = Path(executable).resolve()
    require(compiler_path.is_file(), f"compiler executable is unsafe: {compiler_path}")
    try:
        version = subprocess.run(
            [compiler, "--version"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise HeaderDeclarationInventoryError(f"cannot run compiler --version: {error}") from error
    require(version.returncode == 0, f"compiler --version failed: {version.stderr.strip()}")
    try:
        resource_query = subprocess.run(
            [compiler, "-print-resource-dir"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise HeaderDeclarationInventoryError(f"cannot run compiler -print-resource-dir: {error}") from error
    require(
        resource_query.returncode == 0 and resource_query.stdout.strip(),
        f"compiler -print-resource-dir failed: {resource_query.stderr.strip()}",
    )
    resource_directory_text = resource_query.stdout
    require(
        resource_directory_text.endswith("\n")
        and resource_directory_text.count("\n") == 1,
        "compiler -print-resource-dir did not produce one newline-terminated directory",
    )
    resource_directory = normalized_absolute_observation(
        resource_directory_text[:-1], "compiler resource directory observation"
    )
    resource_include = Path(resource_directory) / "include"
    require(resource_include.is_dir(), f"compiler resource include directory is missing: {resource_include}")
    return (
        {
            "executable_path": str(compiler_path),
            "requested": compiler,
            "resource_include_path": str(resource_include),
            "resource_query_command": [compiler, "-print-resource-dir"],
            "resource_query_returncode": resource_query.returncode,
            "resource_query_stderr": resource_query.stderr,
            "resource_query_stdout": resource_query.stdout,
            "version_command": [compiler, "--version"],
            "version_returncode": version.returncode,
            "version_stderr": version.stderr,
            "version_stdout": version.stdout,
        },
        resource_include,
    )


def normalized_repository_path(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def selection_source_snapshot(project_include: Path) -> tuple[dict[str, Any], abi_matrix.MatrixContract, list[str], list[str]]:
    """Read only current selecting source contracts; never invoke a compiler or oracle."""
    project_include = require_physical_directory(normalized_repository_path(project_include), "project include root")
    contract = abi_matrix.load_contract()
    pinned_headers = callable_inventory.load_headers(contract.public_headers)
    candidate_headers = callable_inventory.candidate_header_paths(project_include, pinned_headers)
    source_digests = {
        relative: sha256_file(ROOT / relative)
        for relative in SOURCE_CONTRACT_FILES
    }
    return (
        {
            "candidate_headers": candidate_headers,
            "candidate_include_tree_sha256": abi_matrix.header_tree_digest(project_include),
            "header_abi_matrix_contract_sha256": sha256_file(abi_matrix.CONTRACT_PATH),
            "oracle_not_applicable": abi_matrix.oracle_exception_records(contract.oracle_not_applicable),
            "pinned_headers": pinned_headers,
            "profiles": profile_records(contract.profiles),
            "public_headers_sha256": sha256_file(contract.public_headers),
            "source_contract_sha256": source_digests,
        },
        contract,
        candidate_headers,
        pinned_headers,
    )


def collection_inputs(
    *,
    compiler: str,
    project_include: Path,
    musl_include: Path,
    linux_uapi_include: Path,
) -> tuple[dict[str, Any], abi_matrix.MatrixContract, Path, list[str], list[str]]:
    """Resolve live compiler/oracle inputs for collection only, never replay."""
    project_include = require_physical_directory(normalized_repository_path(project_include), "project include root")
    musl_include = normalized_repository_path(musl_include)
    linux_uapi_include = normalized_repository_path(linux_uapi_include)
    selection_source, contract, candidate_headers, pinned_headers = selection_source_snapshot(project_include)
    callable_inventory.require_pinned_musl_include(musl_include)
    callable_inventory.require_pinned_linux_uapi_include(linux_uapi_include)
    musl_include = require_physical_directory(musl_include, "pinned musl include root")
    linux_uapi_include = require_physical_directory(linux_uapi_include, "Linux UAPI include root")
    require(
        callable_inventory.public_header_paths(musl_include) == pinned_headers,
        "pinned musl public header tree drifted",
    )
    compiler_record, resource_include = command_identity(compiler)
    resource_include = require_physical_directory(resource_include, "compiler resource include root")
    image_id = os.environ.get("CRABC_X86_HEADER_DECLARATION_IMAGE_ID")
    require(
        isinstance(image_id, str) and IMAGE_ID_PATTERN.fullmatch(image_id) is not None,
        "CRABC_X86_HEADER_DECLARATION_IMAGE_ID must be the resolved crabc-core-evidence digest",
    )
    live: dict[str, Any] = {
        "compiler": compiler_record,
        "image_id_observation": image_id,
        "origin_roots": {
            "candidate-header-root": str(project_include),
            "compiler-resource": str(resource_include),
            "linux-uapi": str(linux_uapi_include),
            "pinned-musl-header-root": str(musl_include),
        },
        "oracle_marker_sources": {
            "linux-uapi": str(linux_uapi_include.parent / ".crabc-linux-uapi"),
            "pinned-musl": str(musl_include.parent / ".crabc-oracle"),
        },
        "selection_source": selection_source,
    }
    return live, contract, resource_include, candidate_headers, pinned_headers


def snapshot_source_contracts(output: Path) -> dict[str, Any]:
    records: dict[str, Any] = {}
    for relative in SOURCE_CONTRACT_FILES:
        records[relative] = snapshot_regular_file(
            output,
            ROOT / relative,
            f"inputs/source-contracts/{relative}",
            relative,
        )
    return records


def snapshot_tool_observations(output: Path, live: Mapping[str, Any]) -> dict[str, Any]:
    compiler = live.get("compiler")
    require(isinstance(compiler, Mapping), "live compiler observation is invalid")
    executable = Path(require_string(compiler.get("executable_path"), "live compiler executable path"))
    snapshot = snapshot_regular_file(
        output,
        executable,
        "inputs/toolchain/clang",
        str(executable),
    )
    version_stdout = write_text_artifact(output, output / "inputs/toolchain/clang-version.stdout.txt", require_string(compiler.get("version_stdout"), "live compiler version stdout", allow_empty=True))
    version_stderr = write_text_artifact(output, output / "inputs/toolchain/clang-version.stderr.txt", require_string(compiler.get("version_stderr"), "live compiler version stderr", allow_empty=True))
    resource_stdout = write_text_artifact(output, output / "inputs/toolchain/clang-resource.stdout.txt", require_string(compiler.get("resource_query_stdout"), "live compiler resource stdout", allow_empty=True))
    resource_stderr = write_text_artifact(output, output / "inputs/toolchain/clang-resource.stderr.txt", require_string(compiler.get("resource_query_stderr"), "live compiler resource stderr", allow_empty=True))
    return {
        "executable": snapshot,
        "executable_original_path": str(executable),
        "requested": require_string(compiler.get("requested"), "live compiler requested name"),
        "resource_include_original_path": require_string(compiler.get("resource_include_path"), "live resource include path"),
        "resource_query": {
            "argv": compiler.get("resource_query_command"),
            "returncode": compiler.get("resource_query_returncode"),
            "stderr": resource_stderr,
            "stdout": resource_stdout,
        },
        "version": {
            "argv": compiler.get("version_command"),
            "returncode": compiler.get("version_returncode"),
            "stderr": version_stderr,
            "stdout": version_stdout,
        },
    }


def snapshot_oracle_markers(output: Path, live: Mapping[str, Any]) -> dict[str, Any]:
    sources = live.get("oracle_marker_sources")
    require(isinstance(sources, Mapping) and set(sources) == {"linux-uapi", "pinned-musl"}, "oracle marker source mapping is invalid")
    return {
        key: snapshot_regular_file(
            output,
            Path(require_string(sources[key], f"oracle marker {key} source")),
            f"inputs/oracle-markers/{key}",
            require_string(sources[key], f"oracle marker {key} source"),
        )
        for key in ("linux-uapi", "pinned-musl")
    }


def finalize_source_contracts(records: Mapping[str, Any]) -> dict[str, Any]:
    require(set(records) == set(SOURCE_CONTRACT_FILES), "collector source snapshot roster changed")
    finalized: dict[str, Any] = {}
    for relative in SOURCE_CONTRACT_FILES:
        record = records[relative]
        require(isinstance(record, Mapping) and set(record) == {"after", "before", "retained"}, f"collector source snapshot is invalid: {relative}")
        updated = dict(record)
        updated["after"] = regular_file_identity(ROOT / relative, relative)
        require_strict_equal(updated["before"], updated["after"], f"collector source changed during collection: {relative}")
        finalized[relative] = updated
    return finalized


def retained_inputs(
    *,
    output: Path,
    live: Mapping[str, Any],
    source_contracts: Mapping[str, Any],
    oracle_markers: Mapping[str, Any],
    tool_observations: Mapping[str, Any],
    jobs: Sequence[dict[str, Any]],
    project_include: Path,
) -> dict[str, Any]:
    """Seal live inputs into copies that a host replay can read without /opt or clang."""
    source_contracts = finalize_source_contracts(source_contracts)
    current_selection, _contract, _candidate, _pinned = selection_source_snapshot(project_include)
    expected_selection = live.get("selection_source")
    require_strict_equal(expected_selection, current_selection, "selecting source changed during collection")
    dependency_snapshots = retain_dependency_snapshots(output, jobs)
    # Every direct public header must appear in a retained compiler dependency;
    # otherwise an AST/proprocessor row could claim a finite roster while its
    # root header bytes were never retained for host replay.
    retained_candidate_headers = {
        item["logical_path"]
        for item in dependency_snapshots
        if item["classification"] == "candidate-header-root"
    }
    retained_musl_headers = {
        item["logical_path"]
        for item in dependency_snapshots
        if item["classification"] == "pinned-musl-header-root"
    }
    expected_candidates = set(current_selection["candidate_headers"])
    expected_pinned = set(current_selection["pinned_headers"])
    require(expected_candidates <= retained_candidate_headers, "retained dependency inputs omit a candidate public header")
    require(expected_pinned <= retained_musl_headers, "retained dependency inputs omit a pinned-musl public header")
    return {
        "collector": {
            "id": COLLECTOR_ID,
            "raw_ast_json": True,
            "raw_preprocessor_records": True,
            "source_text_parsing": False,
        },
        "collector_source_contracts": source_contracts,
        "compiler": dict(tool_observations),
        "dependency_snapshots": dependency_snapshots,
        "image_id_observation": require_string(live.get("image_id_observation"), "image ID observation"),
        "oracle_markers": dict(oracle_markers),
        "origin_roots": dict(live.get("origin_roots", {})),
        "selection_source": dict(expected_selection) if isinstance(expected_selection, Mapping) else expected_selection,
    }


def current_selecting_source_status(
    inputs: Mapping[str, Any],
    project_include: Path,
) -> dict[str, Any]:
    """Report, rather than trust, whether current selection inputs match the seal."""
    retained = inputs.get("selection_source")
    require(isinstance(retained, Mapping), "retained selection source is invalid")
    try:
        current, _contract, _candidate, _pinned = selection_source_snapshot(project_include)
    except ValueError as error:
        return {
            "differences": [{"error": str(error), "path": "current_selecting_source"}],
            "matches_retained": False,
        }
    if strict_equal(current, retained):
        return {"differences": [], "matches_retained": True}
    differences: list[dict[str, Any]] = []
    keys = sorted(set(current) | set(retained))
    for key in keys:
        if key not in current:
            differences.append({"current": None, "path": key, "retained": retained[key]})
        elif key not in retained:
            differences.append({"current": current[key], "path": key, "retained": None})
        elif not strict_equal(current[key], retained[key]):
            differences.append({"current": current[key], "path": key, "retained": retained[key]})
    return {"differences": differences, "matches_retained": False}


def location_fields(
    location: object,
    locations: Mapping[int, tuple[str | None, int | None]],
) -> tuple[int | None, int | None, int | None, int | None]:
    line = callable_inventory.source_line_for_location(location, locations)
    column: int | None = None
    offset: int | None = None
    token_length: int | None = None
    if isinstance(location, Mapping):
        raw_column = location.get("col")
        raw_offset = location.get("offset")
        raw_token_length = location.get("tokLen")
        column = raw_column if type(raw_column) is int and raw_column > 0 else None
        offset = raw_offset if type(raw_offset) is int and raw_offset >= 0 else None
        token_length = raw_token_length if type(raw_token_length) is int and raw_token_length >= 0 else None
    return line, column, offset, token_length


def node_linkage_status(
    *,
    storage_class: str | None,
    source_language: str,
    linkage_specifier_languages: list[str],
) -> str:
    if storage_class == "static":
        return "source-static"
    if storage_class == "extern" and (source_language == "c" or "C" in linkage_specifier_languages):
        return "source-external-declaration"
    return "unresolved-from-json"


def node_definition_observation(node: Mapping[str, Any], storage_class: str | None) -> str:
    children = node.get("inner")
    if isinstance(children, list) and any(
        isinstance(child, Mapping) and child.get("kind") == "CompoundStmt" for child in children
    ):
        return "function-body-present"
    if "init" in node:
        return "initializer-present"
    if storage_class == "extern":
        return "extern-declaration-without-initializer"
    return "unresolved-from-json"


def lexical_header_relative_path(path_text: str | None, header_root: Path) -> str | None:
    """Map a raw compiler path to an observed root without reading that path."""
    if not isinstance(path_text, str) or not path_text or path_text.startswith("<"):
        return None
    try:
        path = Path(os.path.normpath(path_text))
        root = Path(os.path.normpath(str(header_root)))
        return path.relative_to(root).as_posix()
    except ValueError:
        return None


def direct_physical_source(
    *,
    node: Mapping[str, Any],
    header_root: Path,
    input_header: str,
    locations: Mapping[int, tuple[str | None, int | None]],
) -> tuple[str | None, str | None]:
    location = node.get("loc")
    recovered_file, _recovered_line = callable_inventory.resolved_source_location(location, locations)
    source = lexical_header_relative_path(recovered_file, header_root)
    if source is not None:
        return source, "physical"
    if (
        recovered_file is None
        and abi_matrix.is_compact_source_location(location)
        and not abi_matrix.has_explicit_source_file(location)
    ):
        # Never turn an include-stack location into a physical owner.  The
        # direct include boundary is kept as an explicit fallback only when
        # global compact-location recovery has no physical source at all.  A
        # recovered foreign path is excluded, never relabelled as this header.
        return input_header, "primary-include-fallback"
    return None, None


def raw_type_observation(node: Mapping[str, Any]) -> tuple[str | None, str | None]:
    type_info = node.get("type")
    if not isinstance(type_info, Mapping):
        return None, None
    qualified = type_info.get("qualType")
    desugared = type_info.get("desugaredQualType")
    return (
        qualified if isinstance(qualified, str) and qualified else None,
        desugared if isinstance(desugared, str) and desugared else None,
    )


def discover_declaration_occurrences(
    ast: Mapping[str, Any],
    *,
    header_root: Path,
    tree: str,
    input_header: str,
    profile: str,
    raw_ast_path: str,
    source_language: str | None = None,
) -> list[dict[str, Any]]:
    """Retain every header-owned FunctionDecl and file-scope VarDecl in AST order."""
    require(tree in {"candidate", "reference"}, "declaration tree is invalid")
    require_string(input_header, "input header")
    require_string(profile, "profile")
    safe_relative_path(raw_ast_path, "raw AST path")
    if source_language is None:
        source_language = "cxx" if profile.startswith("cxx") else "c"
    require(source_language in {"c", "cxx"}, "source language is invalid")
    locations = callable_inventory.reconstruct_source_locations(ast)
    records: list[dict[str, Any]] = []
    node_ids: dict[str, int] = {}
    stack: list[tuple[Mapping[str, Any], bool, tuple[str, ...]]] = [(ast, False, ())]
    ast_node_ordinal = 0
    while stack:
        node, inside_non_file_scope, linkage_languages = stack.pop()
        node_ordinal = ast_node_ordinal
        ast_node_ordinal += 1
        kind = node.get("kind")
        current_linkage = linkage_languages
        if kind == "LinkageSpecDecl":
            language = node.get("language")
            if isinstance(language, str) and language:
                current_linkage = (*linkage_languages, language)
        child_non_file_scope = inside_non_file_scope or kind in NON_FILE_SCOPE_KINDS
        inner = node.get("inner")
        if isinstance(inner, list):
            stack.extend(
                (child, child_non_file_scope, current_linkage)
                for child in reversed(inner)
                if isinstance(child, Mapping)
            )
        if kind not in {"FunctionDecl", "VarDecl"} or (kind == "VarDecl" and inside_non_file_scope):
            continue
        name = node.get("name")
        if not isinstance(name, str) or not name:
            continue
        declaring_header, origin_resolution = direct_physical_source(
            node=node,
            header_root=header_root,
            input_header=input_header,
            locations=locations,
        )
        if declaring_header is None or origin_resolution is None:
            continue
        location = node.get("loc")
        line, column, offset, token_length = location_fields(location, locations)
        storage = node.get("storageClass")
        storage_class = storage if isinstance(storage, str) and storage else None
        tls = node.get("tls")
        tls_observation = tls if isinstance(tls, str) and tls else None
        qualified_type, desugared_qualified_type = raw_type_observation(node)
        raw_node_id = node.get("id")
        node_id = raw_node_id if isinstance(raw_node_id, str) and raw_node_id else None
        prior = node.get("previousDecl")
        if isinstance(prior, str) and prior:
            if prior in node_ids:
                previous_declaration: dict[str, Any] = {
                    "kind": "same-ast",
                    "occurrence_ordinal": node_ids[prior],
                }
            else:
                previous_declaration = {
                    "kind": "prior-outside-retained-occurrences",
                    "raw_node_id": prior,
                }
        else:
            previous_declaration = {"kind": "none"}
        modeled_keys = {
            "id",
            "kind",
            "name",
            "loc",
            "range",
            "storageClass",
            "tls",
            "type",
            "mangledName",
            "previousDecl",
            "init",
            "inner",
        }
        record = {
            "ast_node_ordinal": node_ordinal,
            "definition_observation": node_definition_observation(node, storage_class),
            "input_header": input_header,
            "kind": "function" if kind == "FunctionDecl" else "variable",
            "linkage_specifier_languages": list(current_linkage),
            "linkage_status": node_linkage_status(
                storage_class=storage_class,
                source_language=source_language,
                linkage_specifier_languages=list(current_linkage),
            ),
            "mangled_name_observation": (
                node.get("mangledName")
                if isinstance(node.get("mangledName"), str) and node.get("mangledName")
                else None
            ),
            "name": name,
            "occurrence_ordinal": len(records),
            "previous_declaration": previous_declaration,
            "profile": profile,
            "raw_ast_path": raw_ast_path,
            "raw_node_id_observation": node_id,
            "source": {
                "column": column,
                "declaring_header": declaring_header,
                "include_root": "candidate-header-root" if tree == "candidate" else "pinned-musl-header-root",
                "line": line,
                "offset": offset,
                "origin_resolution": origin_resolution,
                "token_length": token_length,
            },
            "source_language": source_language,
            "storage_class_observation": storage_class,
            "tls_observation": tls_observation,
            "tree": tree,
            "type": {
                "desugared_qual_type": desugared_qualified_type,
                "qual_type": qualified_type,
            },
            "unmodeled_node_keys": sorted(
                key for key in node if key not in modeled_keys
            ),
        }
        records.append(record)
        if node_id is not None:
            node_ids[node_id] = record["occurrence_ordinal"]
    return records


def parse_preprocessor_marker(line: str) -> tuple[int, str] | None:
    if not line.startswith("#"):
        return None
    try:
        fields = shlex.split(line[1:].strip())
    except ValueError:
        return None
    if len(fields) < 2 or not fields[0].isdigit() or not isinstance(fields[1], str):
        return None
    return int(fields[0]), fields[1]


def parse_macro_definition(line: str) -> tuple[str, str, str] | None:
    """Parse one Clang ``-E -dD`` logical definition record.

    This intentionally parses compiler output, never header text.  The pinned
    Clang receipt for the multiline `sched.h` CPU macros emits one normalized
    logical ``#define`` line per macro; the retained raw preprocessor artifact
    remains authoritative if that compiler behavior ever changes.
    """
    prefix = "#define "
    if not line.startswith(prefix):
        return None
    directive = line[len(prefix) :]
    index = 0
    while index < len(directive) and (directive[index].isalnum() or directive[index] == "_"):
        index += 1
    name = directive[:index]
    if not name:
        return None
    form = "function-like" if index < len(directive) and directive[index] == "(" else "object-like"
    return name, form, directive[index:]


def parse_macro_undefinition(line: str) -> str | None:
    prefix = "#undef "
    if not line.startswith(prefix):
        return None
    name = line[len(prefix) :].strip()
    if not name or any(not (item.isalnum() or item == "_") for item in name):
        return None
    return name


def physical_header_from_marker(path_text: str, header_root: Path) -> str | None:
    return lexical_header_relative_path(path_text, header_root)


def discover_macro_events(
    preprocessed: str,
    *,
    header_root: Path,
    tree: str,
    input_header: str,
    profile: str,
    raw_preprocessor_path: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Keep ordered physical-header macro events and a separate final-active view.

    State is updated for every compiler-emitted definition/undefinition.  The
    reported event stream is narrowed to the physical header root, but an
    outside-root ``#undef`` can still clear a previously public macro in the
    final-active view.  The unfiltered compiler stream remains in the retained
    raw preprocessor artifact.
    """
    require(tree in {"candidate", "reference"}, "macro tree is invalid")
    safe_relative_path(raw_preprocessor_path, "raw preprocessor path")
    events: list[dict[str, Any]] = []
    active: dict[str, dict[str, Any]] = {}
    current_marker_path: str | None = None
    current_marker_line: int | None = None
    preprocessor_ordinal = 0
    for raw_line in preprocessed.splitlines():
        marker = parse_preprocessor_marker(raw_line)
        if marker is not None:
            current_marker_line, current_marker_path = marker
            continue
        definition = parse_macro_definition(raw_line)
        undefined = parse_macro_undefinition(raw_line)
        if definition is None and undefined is None:
            if current_marker_line is not None:
                current_marker_line += 1
            continue
        declaring_header = (
            physical_header_from_marker(current_marker_path, header_root)
            if current_marker_path is not None
            else None
        )
        source = {
            "declaring_header": declaring_header,
            "include_root": "candidate-header-root" if tree == "candidate" else "pinned-musl-header-root",
            "line": current_marker_line,
            "origin_resolution": "physical" if declaring_header is not None else "outside-header-root",
        }
        if definition is not None:
            name, form, replacement = definition
            state = {
                "defining_preprocessor_ordinal": preprocessor_ordinal,
                "form": form,
                "name": name,
                "replacement": replacement,
                "source": source,
            }
            active[name] = state
            if declaring_header is not None:
                events.append(
                    {
                        "event": "define",
                        "form": form,
                        "input_header": input_header,
                        "name": name,
                        "ordinal": len(events),
                        "preprocessor_ordinal": preprocessor_ordinal,
                        "profile": profile,
                        "raw_preprocessor_path": raw_preprocessor_path,
                        "replacement": replacement,
                        "source": source,
                        "tree": tree,
                    }
                )
        else:
            assert undefined is not None
            active.pop(undefined, None)
            if declaring_header is not None:
                events.append(
                    {
                        "event": "undef",
                        "form": None,
                        "input_header": input_header,
                        "name": undefined,
                        "ordinal": len(events),
                        "preprocessor_ordinal": preprocessor_ordinal,
                        "profile": profile,
                        "raw_preprocessor_path": raw_preprocessor_path,
                        "replacement": None,
                        "source": source,
                        "tree": tree,
                    }
                )
        preprocessor_ordinal += 1
        if current_marker_line is not None:
            current_marker_line += 1
    final_active = [
        {
            "defining_preprocessor_ordinal": value["defining_preprocessor_ordinal"],
            "form": value["form"],
            "input_header": input_header,
            "name": name,
            "profile": profile,
            "raw_preprocessor_path": raw_preprocessor_path,
            "replacement": value["replacement"],
            "source": value["source"],
            "tree": tree,
        }
        for name, value in sorted(active.items())
        if value["source"]["declaring_header"] is not None
    ]
    return events, final_active


def derived_summary(
    occurrences: Sequence[Mapping[str, Any]],
    macro_events: Sequence[Mapping[str, Any]],
    final_active_macros: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    linkage = Counter(str(record["linkage_status"]) for record in occurrences)
    kinds = Counter(str(record["kind"]) for record in occurrences)
    return {
        "final_active_macro_count": len(final_active_macros),
        "macro_event_count": len(macro_events),
        "occurrence_count": len(occurrences),
        "occurrence_kind_counts": dict(sorted(kinds.items())),
        "unresolved_linkage_occurrence_count": linkage.get("unresolved-from-json", 0),
        "unresolved_linkage_reasons": (
            ["Clang JSON has no complete linkage observation for one or more retained declarations"]
            if linkage.get("unresolved-from-json", 0)
            else []
        ),
    }


def derive_raw_records_for_replay(
    *,
    ast_json: Mapping[str, Any],
    preprocessed: str,
    header_root: Path,
    tree: str,
    input_header: str,
    profile: str,
    raw_ast_path: str,
    raw_preprocessor_path: str,
    source_language: str | None = None,
) -> dict[str, Any]:
    occurrences = discover_declaration_occurrences(
        ast_json,
        header_root=header_root,
        tree=tree,
        input_header=input_header,
        profile=profile,
        raw_ast_path=raw_ast_path,
        source_language=source_language,
    )
    macro_events, final_active_macros = discover_macro_events(
        preprocessed,
        header_root=header_root,
        tree=tree,
        input_header=input_header,
        profile=profile,
        raw_preprocessor_path=raw_preprocessor_path,
    )
    return {
        "final_active_macros": final_active_macros,
        "macro_events": macro_events,
        "occurrences": occurrences,
        "summary": derived_summary(occurrences, macro_events, final_active_macros),
    }


def validate_derived_records(observed: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    require(set(observed) == {"occurrences", "macro_events", "final_active_macros", "summary"}, "derived raw record keys changed")
    summary = observed.get("summary")
    require(isinstance(summary, Mapping), "derived raw summary is invalid")
    for key in (
        "occurrence_count",
        "macro_event_count",
        "final_active_macro_count",
        "unresolved_linkage_occurrence_count",
    ):
        require_integer(summary.get(key), f"derived raw summary.{key}", minimum=0)
    require_strict_equal(observed, expected, "derived declaration occurrences")


def normalized_observed_path(path_text: str) -> str:
    return os.path.normpath(path_text)


def dependency_record(
    path_text: str,
    *,
    source: Path,
    header_root: Path,
    resource_include: Path,
    linux_uapi_include: Path,
    header_root_classification: str,
) -> dict[str, Any] | None:
    """Describe one physical compiler dependency while collection roots exist."""
    if not path_text or path_text.startswith("<"):
        return None
    try:
        path = Path(path_text).resolve(strict=True)
    except OSError as error:
        raise HeaderDeclarationInventoryError(
            f"compiler dependency cannot be retained: {path_text} ({error})"
        ) from error
    original = str(path)
    if path == source.resolve():
        return {
            "classification": "probe",
            "logical_path": source.name,
            "original_path_observation": original,
        }
    require(header_root_classification in {"candidate-header-root", "pinned-musl-header-root"}, "header dependency classification is invalid")
    for root, classification in (
        (header_root, header_root_classification),
        (resource_include, "compiler-resource"),
        (linux_uapi_include, "linux-uapi"),
    ):
        try:
            relative = path.relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
        require(path.is_file() and not path.is_symlink(), f"compiler dependency is unsafe: {path}")
        return {
            "classification": classification,
            "logical_path": relative,
            "original_path_observation": original,
        }
    require(path.is_file() and not path.is_symlink(), f"compiler external dependency is unsafe: {path}")
    return {
        "classification": "external-physical",
        "logical_path": path.name,
        "original_path_observation": original,
    }


def dependency_records(
    preprocessed: str,
    *,
    source: Path,
    header_root: Path,
    resource_include: Path,
    linux_uapi_include: Path,
    header_root_classification: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in preprocessed.splitlines():
        marker = parse_preprocessor_marker(line)
        if marker is None:
            continue
        record = dependency_record(
            marker[1],
            source=source,
            header_root=header_root,
            resource_include=resource_include,
            linux_uapi_include=linux_uapi_include,
            header_root_classification=header_root_classification,
        )
        if record is None:
            continue
        original = record["original_path_observation"]
        if original in seen:
            continue
        seen.add(original)
        records.append(record)
    return sorted(records, key=lambda item: item["original_path_observation"])


def dependency_key(classification: str, logical_path: str, original_path: str) -> str:
    safe_relative_path(logical_path, "dependency logical path")
    if classification in {"external-physical", "probe"}:
        return f"{classification}/{sha256_bytes(original_path.encode('utf-8'))[:16]}-{logical_path}"
    return f"{classification}/{logical_path}"


def retain_dependency_snapshots(
    output: Path,
    jobs: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Copy every physically observed PP dependency and replace job paths with keys."""
    observed: dict[str, dict[str, Any]] = {}
    for job in jobs:
        dependencies = job.get("dependencies")
        require(isinstance(dependencies, list), "live job dependencies are invalid")
        for item in dependencies:
            require(isinstance(item, Mapping), "live dependency is invalid")
            original = require_string(item.get("original_path_observation"), "live dependency original path")
            prior = observed.get(original)
            rendered = dict(item)
            if prior is None:
                observed[original] = rendered
            else:
                require_strict_equal(prior, rendered, f"dependency origin mapping {original}")
    retained: list[dict[str, Any]] = []
    by_original: dict[str, str] = {}
    used_keys: set[str] = set()
    for original in sorted(observed):
        item = observed[original]
        classification = require_string(item.get("classification"), "dependency classification")
        logical = require_string(item.get("logical_path"), "dependency logical path")
        key = dependency_key(classification, logical, original)
        require(key not in used_keys, f"dependency retained key is ambiguous: {key}")
        used_keys.add(key)
        retained_relative = f"inputs/dependencies/{key}"
        snapshot = snapshot_regular_file(output, Path(original), retained_relative, original)
        retained.append(
            {
                "classification": classification,
                "key": key,
                "logical_path": logical,
                "original_path_observation": original,
                "snapshot": snapshot,
            }
        )
        by_original[original] = key
    for job in jobs:
        dependencies = job["dependencies"]
        job["dependencies"] = sorted(
            by_original[require_string(item["original_path_observation"], "live dependency original path")]
            for item in dependencies
        )
    return retained


def dependency_keys_from_preprocessed(
    preprocessed: str,
    dependency_snapshots: Sequence[Mapping[str, Any]],
) -> list[str]:
    mapping: dict[str, str] = {}
    for index, item in enumerate(dependency_snapshots):
        require(isinstance(item, Mapping), f"retained dependency {index} is invalid")
        original = require_string(item.get("original_path_observation"), f"retained dependency {index}.original path")
        key = require_string(item.get("key"), f"retained dependency {index}.key")
        require(original not in mapping, f"retained dependency original path is duplicated: {original}")
        mapping[original] = key
    result: set[str] = set()
    for line in preprocessed.splitlines():
        marker = parse_preprocessor_marker(line)
        if marker is None or not marker[1] or marker[1].startswith("<"):
            continue
        observed = normalized_observed_path(marker[1])
        require(observed in mapping, f"raw preprocessor dependency has no retained mapping: {marker[1]}")
        result.add(mapping[observed])
    return sorted(result)


def artifact_descriptor(output: Path, path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"raw artifact is unsafe: {path}")
    relative = path.relative_to(output).as_posix()
    return {"path": relative, "sha256": sha256_file(path), "size": path.stat().st_size}


def write_text_artifact(output: Path, path: Path, value: str) -> dict[str, Any]:
    path.write_text(value, encoding="utf-8")
    return artifact_descriptor(output, path)


def write_json_artifact(output: Path, path: Path, value: object) -> dict[str, Any]:
    write_json(path, value)
    return artifact_descriptor(output, path)


def job_directory(output: Path, tree: str, header: str, profile: str) -> Path:
    require(tree in {"candidate", "reference"}, "job tree is invalid")
    relative_header = safe_relative_path(header, "job header")
    require_string(profile, "job profile")
    destination = output / "raw" / tree / relative_header / profile
    destination.mkdir(parents=True, exist_ok=False)
    return require_physical_directory(destination, "raw job directory")


def source_language_for_profile(profile: callable_inventory.Profile) -> str:
    return profile.language


def collect_one_job(
    *,
    output: Path,
    ordinal: int,
    tree: str,
    header: str,
    profile: callable_inventory.Profile,
    header_root: Path,
    resource_include: Path,
    linux_uapi_include: Path,
    oracle_not_applicable: Mapping[tuple[str, str], str],
    compiler: str,
    timeout_seconds: float,
    job_control: abi_matrix.CompilerJobControl,
) -> tuple[dict[str, Any], dict[str, Any]]:
    directory = job_directory(output, tree, header, profile.identifier)
    result = abi_matrix.compiler_profile_raw_artifacts(
        compiler=compiler,
        profile=profile,
        header=header,
        header_root=header_root,
        resource_include=resource_include,
        linux_uapi_include=linux_uapi_include,
        work_dir=directory,
        timeout_seconds=timeout_seconds,
        job_control=job_control,
    )
    temporary = directory / "tmp"
    if temporary.exists():
        require(temporary.is_dir() and not temporary.is_symlink(), f"compiler temporary directory is unsafe: {temporary}")
        shutil.rmtree(temporary)
    status = result.status
    detail = result.detail
    if status == "failed" and tree == "reference" and (header, profile.identifier) in oracle_not_applicable:
        status = "oracle-not-applicable"
        detail = oracle_not_applicable[(header, profile.identifier)]
    ast_path = directory / "ast.json"
    artifacts: dict[str, dict[str, Any]] = {
        "ast_command": write_json_artifact(output, directory / "ast.command.json", list(result.ast_command)),
        "ast_stderr": write_text_artifact(output, directory / "ast.stderr.txt", result.ast_stderr),
        "ast_stdout": write_text_artifact(output, ast_path, result.ast_stdout),
        "source": artifact_descriptor(output, result.source),
    }
    if result.preprocess_command is not None:
        artifacts["preprocessor_command"] = write_json_artifact(
            output, directory / "preprocessor.command.json", list(result.preprocess_command)
        )
        artifacts["preprocessor_stderr"] = write_text_artifact(
            output, directory / "preprocessor.stderr.txt", result.preprocess_stderr or "")
        artifacts["preprocessor_stdout"] = write_text_artifact(
            output, directory / "preprocessor.txt", result.preprocess_stdout or "")
    probe_dependency = dependency_record(
        str(result.source),
        source=result.source,
        header_root=header_root,
        resource_include=resource_include,
        linux_uapi_include=linux_uapi_include,
        header_root_classification=(
            "candidate-header-root" if tree == "candidate" else "pinned-musl-header-root"
        ),
    )
    require(
        probe_dependency is not None and probe_dependency["classification"] == "probe",
        f"raw compiler probe dependency is missing for {tree}:{header}:{profile.identifier}",
    )
    dependencies: list[dict[str, Any]] = [probe_dependency]
    derived = {
        "occurrences": [],
        "macro_events": [],
        "final_active_macros": [],
        "summary": derived_summary([], [], []),
    }
    if result.status == "ok":
        try:
            ast = json.loads(result.ast_stdout)
        except json.JSONDecodeError as error:
            raise HeaderDeclarationInventoryError(
                f"raw AST is invalid for {tree}:{header}:{profile.identifier}: {error}"
            ) from error
        ast = validate_clang_translation_unit(
            ast, f"raw AST for {tree}:{header}:{profile.identifier}"
        )
        preprocessed = result.preprocess_stdout
        require(isinstance(preprocessed, str), f"raw preprocessor output is missing for {tree}:{header}:{profile.identifier}")
        raw_ast_path = artifacts["ast_stdout"]["path"]
        raw_pp_path = artifacts["preprocessor_stdout"]["path"]
        derived = derive_raw_records_for_replay(
            ast_json=ast,
            preprocessed=preprocessed,
            header_root=header_root,
            tree=tree,
            input_header=header,
            profile=profile.identifier,
            raw_ast_path=raw_ast_path,
            raw_preprocessor_path=raw_pp_path,
            source_language=source_language_for_profile(profile),
        )
        dependencies = dependency_records(
            preprocessed,
            source=result.source,
            header_root=header_root,
            resource_include=resource_include,
            linux_uapi_include=linux_uapi_include,
            header_root_classification=(
                "candidate-header-root" if tree == "candidate" else "pinned-musl-header-root"
            ),
        )
        require(
            any(item["classification"] == "probe" and item["original_path_observation"] == probe_dependency["original_path_observation"] for item in dependencies),
            f"raw preprocessor does not retain its probe marker for {tree}:{header}:{profile.identifier}",
        )
    status_payload = {
        "ast_returncode": result.ast_returncode,
        "detail": detail,
        "preprocess_returncode": result.preprocess_returncode,
        "schema": RAW_ARTIFACT_SCHEMA,
        "status": status,
    }
    artifacts["status"] = write_json_artifact(output, directory / "status.json", status_payload)
    job = {
        "artifacts": artifacts,
        "dependencies": dependencies,
        "detail": detail,
        "header": header,
        "ordinal": ordinal,
        "probe_original_path_observation": str(result.source.resolve()),
        "profile": profile.identifier,
        "status": status,
        "tree": tree,
    }
    return job, derived


def job_plan(
    contract: abi_matrix.MatrixContract,
    candidate_headers: Sequence[str],
    pinned_headers: Sequence[str],
) -> list[tuple[str, str, callable_inventory.Profile]]:
    return [
        *( ("candidate", header, profile) for header in candidate_headers for profile in contract.profiles ),
        *( ("reference", header, profile) for header in pinned_headers for profile in contract.profiles ),
    ]


def collect_raw_jobs(
    *,
    output: Path,
    compiler: str,
    contract: abi_matrix.MatrixContract,
    resource_include: Path,
    project_include: Path,
    musl_include: Path,
    linux_uapi_include: Path,
    candidate_headers: Sequence[str],
    pinned_headers: Sequence[str],
    workers: int,
    timeout_seconds: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    workers = abi_matrix.bounded_collection_workers(workers)
    require(
        isinstance(timeout_seconds, (int, float))
        and not isinstance(timeout_seconds, bool)
        and math.isfinite(float(timeout_seconds))
        and timeout_seconds > 0,
        "compiler job timeout must be positive",
    )
    plan = job_plan(contract, candidate_headers, pinned_headers)
    jobs: dict[int, dict[str, Any]] = {}
    derived: dict[int, dict[str, Any]] = {}
    control = abi_matrix.CompilerJobControl()
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="header-declaration-clang")
    futures: dict[Any, int] = {}
    try:
        for ordinal, (tree, header, profile) in enumerate(plan):
            future = executor.submit(
                collect_one_job,
                output=output,
                ordinal=ordinal,
                tree=tree,
                header=header,
                profile=profile,
                header_root=project_include if tree == "candidate" else musl_include,
                resource_include=resource_include,
                linux_uapi_include=linux_uapi_include,
                oracle_not_applicable=contract.oracle_not_applicable,
                compiler=compiler,
                timeout_seconds=float(timeout_seconds),
                job_control=control,
            )
            futures[future] = ordinal
        for future in as_completed(futures):
            ordinal = futures[future]
            job, records = future.result()
            jobs[ordinal] = job
            derived[ordinal] = records
    except KeyboardInterrupt:
        control.cancel()
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        raise
    except BaseException as error:
        control.cancel()
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        raise HeaderDeclarationInventoryError(f"raw declaration compiler collection failed: {error}") from error
    else:
        executor.shutdown(wait=True)
    ordered_jobs = [jobs[index] for index in range(len(plan))]
    failed = [job for job in ordered_jobs if job["status"] == "failed"]
    require(not failed, f"compiler declaration collection has {len(failed)} unexpected failed rows")
    observed_exceptions = {
        (job["header"], job["profile"])
        for job in ordered_jobs
        if job["tree"] == "reference" and job["status"] == "oracle-not-applicable"
    }
    require(
        observed_exceptions == set(contract.oracle_not_applicable),
        "configured oracle-not-applicable rows were not represented exactly during collection",
    )
    occurrences = [record for index in range(len(plan)) for record in derived[index]["occurrences"]]
    macro_events = [record for index in range(len(plan)) for record in derived[index]["macro_events"]]
    final_active_macros = [record for index in range(len(plan)) for record in derived[index]["final_active_macros"]]
    return ordered_jobs, occurrences, macro_events, final_active_macros


def raw_artifact_paths(jobs: Sequence[Mapping[str, Any]]) -> set[str]:
    paths: set[str] = set()
    for job in jobs:
        artifacts = job.get("artifacts")
        require(isinstance(artifacts, Mapping), "raw job artifacts are invalid")
        for label, descriptor in artifacts.items():
            require(isinstance(label, str) and label, "raw job artifact label is invalid")
            require(isinstance(descriptor, Mapping), f"raw job artifact {label} is invalid")
            relative = safe_relative_path(descriptor.get("path"), f"raw job artifact {label}.path")
            require(relative.parts and relative.parts[0] == "raw", f"raw job artifact {label} escapes raw directory")
            rendered = relative.as_posix()
            require(rendered not in paths, f"raw job artifact path is duplicated: {rendered}")
            paths.add(rendered)
    return paths


def output_raw_paths(output: Path) -> set[str]:
    raw = output / "raw"
    require(raw.is_dir() and not raw.is_symlink(), "raw evidence directory is missing or unsafe")
    paths: set[str] = set()
    for path in raw.rglob("*"):
        require(not path.is_symlink(), f"raw evidence contains a symlink: {path.relative_to(output)}")
        if path.is_dir():
            continue
        require(path.is_file(), f"raw evidence contains an unsupported entry: {path.relative_to(output)}")
        paths.add(path.relative_to(output).as_posix())
    return paths


def descriptor_path(output: Path, descriptor: Mapping[str, Any], location: str) -> Path:
    relative = safe_relative_path(descriptor.get("path"), f"{location}.path")
    require(type(descriptor.get("size")) is int and descriptor["size"] >= 0, f"{location}.size is invalid")
    digest = require_string(descriptor.get("sha256"), f"{location}.sha256")
    require(len(digest) == 64 and all(character in "0123456789abcdef" for character in digest), f"{location}.sha256 is invalid")
    path = output / relative
    require(path.is_file() and not path.is_symlink(), f"{location} is missing or unsafe")
    require(path.stat().st_size == descriptor["size"], f"{location} size drifted")
    require(sha256_file(path) == digest, f"{location} digest drifted")
    return path


def read_artifact_json(output: Path, descriptor: Mapping[str, Any], location: str) -> object:
    path = descriptor_path(output, descriptor, location)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HeaderDeclarationInventoryError(f"cannot read {location}: {error}") from error


def read_artifact_text(output: Path, descriptor: Mapping[str, Any], location: str) -> str:
    path = descriptor_path(output, descriptor, location)
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise HeaderDeclarationInventoryError(f"cannot read {location}: {error}") from error


def validate_clang_translation_unit(ast: object, location: str) -> Mapping[str, Any]:
    require(isinstance(ast, Mapping), f"{location} root is invalid")
    require(ast.get("kind") == "TranslationUnitDecl", f"{location} is not a Clang translation unit")
    require(isinstance(ast.get("inner"), list), f"{location} translation unit children are invalid")
    return ast


def validate_job_artifact_descriptors(
    output: Path,
    artifacts: Mapping[str, Any],
) -> None:
    """Verify every advertised raw compiler artifact, including stderr files."""
    for label in sorted(artifacts):
        descriptor = artifacts[label]
        require(isinstance(descriptor, Mapping), f"raw job artifact {label} is invalid")
        path = descriptor_path(output, descriptor, f"raw job artifact {label}")
        relative = path.relative_to(output).as_posix()
        require(relative.startswith("raw/"), f"raw job artifact {label} escapes raw evidence")


def validate_job_artifact_paths(
    artifacts: Mapping[str, Any],
    *,
    tree: str,
    header: str,
    profile: callable_inventory.Profile,
    status: str,
) -> None:
    header_path = safe_relative_path(header, "raw job header")
    profile_path = safe_relative_path(profile.identifier, "raw job profile")
    require(len(profile_path.parts) == 1, "raw job profile is not one path component")
    base = Path("raw") / tree / header_path / profile_path
    expected = {
        "ast_command": base / "ast.command.json",
        "ast_stderr": base / "ast.stderr.txt",
        "ast_stdout": base / "ast.json",
        "source": base / ("probe.cpp" if profile.language == "cxx" else "probe.c"),
        "status": base / "status.json",
    }
    if status == "ok":
        expected.update({
            "preprocessor_command": base / "preprocessor.command.json",
            "preprocessor_stderr": base / "preprocessor.stderr.txt",
            "preprocessor_stdout": base / "preprocessor.txt",
        })
    require(set(artifacts) == set(expected), "raw job artifact path roster changed")
    for label, relative in expected.items():
        descriptor = artifacts[label]
        require(isinstance(descriptor, Mapping), f"raw job artifact {label} is invalid")
        require(
            descriptor.get("path") == relative.as_posix(),
            f"raw job artifact {label} path is not canonical for its job",
        )


def job_dependency_entries(
    dependencies: Sequence[str],
    dependency_keys: Mapping[str, Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    entries: list[Mapping[str, Any]] = []
    for key in dependencies:
        require(key in dependency_keys, "raw job names an unknown retained dependency")
        entries.append(dependency_keys[key])
    return entries


def require_job_probe_dependency(
    *,
    output: Path,
    entries: Sequence[Mapping[str, Any]],
    probe_original: str,
    source_descriptor: Mapping[str, Any],
) -> None:
    probe_entries = [
        item
        for item in entries
        if item.get("classification") == "probe"
        and item.get("original_path_observation") == probe_original
    ]
    require(len(probe_entries) == 1, "raw job source is not bound to exactly one retained probe dependency")
    probe = probe_entries[0]
    require(probe.get("logical_path") == safe_relative_path(source_descriptor.get("path"), "raw source descriptor path").name, "raw job probe logical path drifted")
    snapshot = probe.get("snapshot")
    require(isinstance(snapshot, Mapping), "raw job probe snapshot is invalid")
    retained = snapshot.get("retained")
    require(isinstance(retained, Mapping), "raw job probe retained descriptor is invalid")
    source_path = descriptor_path(output, source_descriptor, "raw source")
    retained_path = descriptor_path(output, retained, "raw job probe retained source")
    require(
        source_path.stat().st_size == retained_path.stat().st_size
        and sha256_file(source_path) == sha256_file(retained_path),
        "raw job probe source bytes are detached from retained dependency",
    )


def require_job_physical_origins(
    records: Sequence[Mapping[str, Any]],
    entries: Sequence[Mapping[str, Any]],
    *,
    tree: str,
    record_kind: str,
) -> None:
    expected_root = "candidate-header-root" if tree == "candidate" else "pinned-musl-header-root"
    available = {
        (item.get("classification"), item.get("logical_path"))
        for item in entries
    }
    for index, record in enumerate(records):
        source = record.get("source")
        require(isinstance(source, Mapping), f"{record_kind} {index} source is invalid")
        origin = source.get("origin_resolution")
        require(origin in {"physical", "primary-include-fallback"}, f"{record_kind} {index} has a nonphysical retained source")
        include_root = source.get("include_root")
        declaring_header = source.get("declaring_header")
        require(include_root == expected_root, f"{record_kind} {index} include root drifted")
        logical = safe_relative_path(declaring_header, f"{record_kind} {index} declaring header").as_posix()
        require(
            (include_root, logical) in available,
            f"{record_kind} {index} physical source has no retained job dependency",
        )


def require_report_keys(report: Mapping[str, Any]) -> None:
    expected = {
        "collection",
        "final_active_macros",
        "inputs",
        "jobs",
        "macro_events",
        "occurrences",
        "oracle",
        "platform",
        "schema",
        "scope",
        "status",
        "summary",
        "target",
    }
    require(set(report) == expected, "declaration inventory report keys changed")
    require(report.get("schema") == SCHEMA, "declaration inventory schema changed")
    require(report.get("target") == TARGET, "declaration inventory target changed")
    require(report.get("platform") == PLATFORM, "declaration inventory platform changed")
    require(report.get("oracle") == ORACLE, "declaration inventory oracle changed")
    scope = report.get("scope")
    require(isinstance(scope, Mapping), "declaration inventory scope is invalid")
    expected_scope = {
        "compiler_ast_json": True,
        "compiler_preprocessor_records": True,
        "function_occurrences_before_collapse": True,
        "header_text_parsing": False,
        "layout_evaluation": False,
        "macro_events_before_collapse": True,
        "provider_selection": False,
        "runtime": False,
        "variable_occurrences_before_collapse": True,
    }
    require_strict_equal(scope, expected_scope, "declaration inventory scope")
    require(isinstance(report.get("inputs"), Mapping), "declaration inventory inputs are invalid")
    require(isinstance(report.get("collection"), Mapping), "declaration inventory collection is invalid")
    require(isinstance(report.get("jobs"), list), "declaration inventory jobs are invalid")
    require(isinstance(report.get("occurrences"), list), "declaration inventory occurrences are invalid")
    require(isinstance(report.get("macro_events"), list), "declaration inventory macro events are invalid")
    require(isinstance(report.get("final_active_macros"), list), "declaration inventory active macros are invalid")
    require(isinstance(report.get("summary"), Mapping), "declaration inventory summary is invalid")
    require(isinstance(report.get("status"), Mapping), "declaration inventory status is invalid")


def selection_source(inputs: Mapping[str, Any]) -> Mapping[str, Any]:
    selection = inputs.get("selection_source")
    require(isinstance(selection, Mapping), "retained selection source is invalid")
    return selection


def retained_source_text(
    output: Path,
    source_contracts: Mapping[str, Any],
    relative: str,
) -> str:
    record = source_contracts[relative]
    require(isinstance(record, Mapping), f"retained collector source {relative} is invalid")
    retained = record.get("retained")
    require(isinstance(retained, Mapping), f"retained collector source {relative} descriptor is invalid")
    path = output / safe_relative_path(retained.get("path"), f"retained collector source {relative}.path")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise HeaderDeclarationInventoryError(f"cannot read retained collector source {relative}: {error}") from error


def validated_header_paths(value: object, location: str) -> list[str]:
    require(isinstance(value, list), f"{location} must be an array")
    paths: list[str] = []
    for index, item in enumerate(value):
        rendered = safe_relative_path(item, f"{location}[{index}]").as_posix()
        paths.append(rendered)
    require(paths == sorted(paths), f"{location} is not ASCII sorted")
    require(len(paths) == len(set(paths)), f"{location} has duplicates")
    return paths


def validated_profile_records(value: object, location: str) -> list[dict[str, Any]]:
    require(isinstance(value, list) and value, f"{location} must be a nonempty array")
    records: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for index, item in enumerate(value):
        require(isinstance(item, Mapping) and set(item) == {"defines", "id", "language", "standard"}, f"{location}[{index}] keys changed")
        identifier = require_string(item["id"], f"{location}[{index}].id")
        identifier_path = safe_relative_path(identifier, f"{location}[{index}].id")
        require(len(identifier_path.parts) == 1, f"{location}[{index}].id is not one profile identifier")
        language = item["language"]
        standard = require_string(item["standard"], f"{location}[{index}].standard")
        defines = item["defines"]
        require(language in {"c", "cxx"}, f"{location}[{index}].language is invalid")
        require(isinstance(defines, list), f"{location}[{index}].defines is invalid")
        rendered_defines: list[str] = []
        for define_index, define in enumerate(defines):
            rendered = require_string(define, f"{location}[{index}].defines[{define_index}]")
            require("\n" not in rendered, f"{location}[{index}].defines[{define_index}] contains a newline")
            rendered_defines.append(rendered)
        require(len(rendered_defines) == len(set(rendered_defines)), f"{location}[{index}].defines has duplicates")
        require(identifier not in identifiers, f"{location} repeats {identifier}")
        identifiers.add(identifier)
        records.append({
            "defines": rendered_defines,
            "id": identifier,
            "language": language,
            "standard": standard,
        })
    return records


def validated_oracle_exception_records(value: object, location: str) -> list[dict[str, str]]:
    require(isinstance(value, list), f"{location} must be an array")
    records: list[dict[str, str]] = []
    identities: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        require(isinstance(item, Mapping) and set(item) == {"header", "profile", "reason"}, f"{location}[{index}] keys changed")
        header = safe_relative_path(item["header"], f"{location}[{index}].header").as_posix()
        profile = require_string(item["profile"], f"{location}[{index}].profile")
        reason = require_string(item["reason"], f"{location}[{index}].reason")
        identity = (header, profile)
        require(identity not in identities, f"{location} repeats {header}:{profile}")
        identities.add(identity)
        records.append({"header": header, "profile": profile, "reason": reason})
    require(records == sorted(records, key=lambda item: (item["header"], item["profile"])), f"{location} is not sorted")
    return records


def retained_toml(text: str, location: str) -> Mapping[str, Any]:
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise HeaderDeclarationInventoryError(f"cannot parse retained {location}: {error}") from error
    require(isinstance(parsed, Mapping), f"retained {location} is not a TOML table")
    return parsed


def validate_selection_source(
    output: Path,
    selection: Mapping[str, Any],
    source_contracts: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Bind finite selection inputs to their retained contract bytes.

    The candidate include-tree digest is intentionally an observed seal: the
    collector retains every public header reached by the finite compiler
    roster, while a host replay cannot reconstruct an arbitrary original
    include tree.  Profiles, reference headers, and reference exceptions are
    recomputed from retained source contracts instead of trusted from JSON.
    """
    expected = {
        "candidate_headers",
        "candidate_include_tree_sha256",
        "header_abi_matrix_contract_sha256",
        "oracle_not_applicable",
        "pinned_headers",
        "profiles",
        "public_headers_sha256",
        "source_contract_sha256",
    }
    require(set(selection) == expected, "retained selection source keys changed")
    source_digests = selection["source_contract_sha256"]
    require(isinstance(source_digests, Mapping) and set(source_digests) == set(SOURCE_CONTRACT_FILES), "retained selection source-contract digest roster changed")
    for relative in SOURCE_CONTRACT_FILES:
        digest = require_sha256(source_digests[relative], f"retained selection source digest {relative}")
        source_record = source_contracts[relative]
        require(isinstance(source_record, Mapping), f"retained collector source {relative} is invalid")
        retained = source_record.get("retained")
        require(isinstance(retained, Mapping), f"retained collector source {relative} descriptor is invalid")
        require(digest == retained.get("sha256"), f"retained selection source digest is detached from {relative}")
    matrix_relative = "compat/x86_64/header_abi_matrix.toml"
    headers_relative = "compat/x86_64/public_headers.txt"
    require(
        require_sha256(selection["header_abi_matrix_contract_sha256"], "retained header ABI matrix contract digest")
        == source_digests[matrix_relative],
        "retained header ABI matrix contract digest is detached from source contracts",
    )
    require(
        require_sha256(selection["public_headers_sha256"], "retained public-header manifest digest")
        == source_digests[headers_relative],
        "retained public-header manifest digest is detached from source contracts",
    )
    require_sha256(selection["candidate_include_tree_sha256"], "retained candidate include-tree digest")
    candidate_headers = validated_header_paths(selection["candidate_headers"], "retained candidate header roster")
    pinned_headers = validated_header_paths(selection["pinned_headers"], "retained pinned-musl header roster")
    profiles = validated_profile_records(selection["profiles"], "retained profile roster")
    exceptions = validated_oracle_exception_records(selection["oracle_not_applicable"], "retained oracle exception roster")
    profile_ids = {item["id"] for item in profiles}
    require(all(row["header"] in pinned_headers for row in exceptions), "retained oracle exception header is absent from pinned roster")
    require(all(row["profile"] in profile_ids for row in exceptions), "retained oracle exception profile is absent from profile roster")

    retained_matrix = retained_toml(retained_source_text(output, source_contracts, matrix_relative), matrix_relative)
    require(retained_matrix.get("public_headers") == headers_relative, "retained header ABI matrix public-header path changed")
    retained_exceptions = validated_oracle_exception_records(
        retained_matrix.get("oracle_not_applicable"), f"retained {matrix_relative}.oracle_not_applicable"
    )
    require_strict_equal(exceptions, retained_exceptions, "retained oracle exception source binding")
    retained_inventory = retained_toml(
        retained_source_text(output, source_contracts, "compat/x86_64/header_callable_inventory.toml"),
        "compat/x86_64/header_callable_inventory.toml",
    )
    retained_profiles = validated_profile_records(
        retained_inventory.get("profile"), "retained header callable inventory profile roster"
    )
    require_strict_equal(profiles, retained_profiles, "retained compiler profile source binding")
    retained_headers = validated_header_paths(
        retained_source_text(output, source_contracts, headers_relative).splitlines(),
        "retained public-header manifest",
    )
    require_strict_equal(pinned_headers, retained_headers, "retained pinned-musl header source binding")
    return selection


def source_language_by_identifier(inputs: Mapping[str, Any]) -> dict[str, str]:
    profiles = validated_profile_records(selection_source(inputs).get("profiles"), "retained profile inputs")
    result: dict[str, str] = {}
    for item in profiles:
        identifier = item["id"]
        language = item["language"]
        require(identifier not in result, f"retained profile {identifier} is duplicated")
        result[identifier] = language
    return result


def profile_by_identifier(inputs: Mapping[str, Any]) -> dict[str, callable_inventory.Profile]:
    profiles = validated_profile_records(selection_source(inputs).get("profiles"), "retained profile inputs")
    result: dict[str, callable_inventory.Profile] = {}
    for item in profiles:
        identifier = item["id"]
        language = item["language"]
        standard = item["standard"]
        defines = item["defines"]
        require(identifier not in result, f"retained profile {identifier} is duplicated")
        result[identifier] = callable_inventory.Profile(identifier, language, standard, tuple(defines))
    return result


def expected_job_identities(inputs: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    selection = selection_source(inputs)
    candidate_headers = selection.get("candidate_headers")
    pinned_headers = selection.get("pinned_headers")
    require(isinstance(candidate_headers, list) and all(isinstance(item, str) for item in candidate_headers), "candidate header input is invalid")
    require(isinstance(pinned_headers, list) and all(isinstance(item, str) for item in pinned_headers), "pinned header input is invalid")
    profiles = source_language_by_identifier(inputs)
    return [
        *(("candidate", header, profile) for header in candidate_headers for profile in profiles),
        *(("reference", header, profile) for header in pinned_headers for profile in profiles),
    ]


def validated_descriptor_paths(
    output: Path,
    descriptor: object,
    location: str,
    paths: set[str],
    *,
    expected_relative: str | None = None,
) -> None:
    require(isinstance(descriptor, Mapping), f"{location} descriptor is invalid")
    path = descriptor_path(output, descriptor, location)
    relative = path.relative_to(output).as_posix()
    if expected_relative is not None:
        require(relative == expected_relative, f"{location} retained path changed")
    require(relative.startswith("inputs/"), f"{location} is outside retained input directory")
    require(relative not in paths, f"retained input artifact is duplicated: {relative}")
    paths.add(relative)


def output_input_paths(output: Path) -> set[str]:
    inputs = output / "inputs"
    require(inputs.is_dir() and not inputs.is_symlink(), "retained input directory is missing or unsafe")
    paths: set[str] = set()
    for path in inputs.rglob("*"):
        require(not path.is_symlink(), f"retained inputs contain a symlink: {path.relative_to(output)}")
        if path.is_dir():
            continue
        require(path.is_file(), f"retained inputs contain an unsupported entry: {path.relative_to(output)}")
        paths.add(path.relative_to(output).as_posix())
    return paths


def retained_resource_include_from_query(
    output: Path,
    descriptor: Mapping[str, Any],
) -> str:
    stdout = read_artifact_text(output, descriptor, "retained compiler resource query stdout")
    require(
        stdout.endswith("\n") and stdout.count("\n") == 1,
        "retained compiler resource query stdout is not one newline-terminated directory",
    )
    resource_directory = normalized_absolute_observation(
        stdout[:-1], "retained compiler resource directory observation"
    )
    return normalized_absolute_observation(
        str(Path(resource_directory) / "include"), "retained compiler resource include observation"
    )


def validate_retained_inputs(output: Path, inputs: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "collector",
        "collector_source_contracts",
        "compiler",
        "dependency_snapshots",
        "image_id_observation",
        "oracle_markers",
        "origin_roots",
        "selection_source",
    }
    require(set(inputs) == expected, "retained input keys changed")
    collector = inputs["collector"]
    require_strict_equal(
        collector,
        {
            "id": COLLECTOR_ID,
            "raw_ast_json": True,
            "raw_preprocessor_records": True,
            "source_text_parsing": False,
        },
        "retained collector contract",
    )
    require(
        IMAGE_ID_PATTERN.fullmatch(require_string(inputs["image_id_observation"], "retained image ID observation")) is not None,
        "retained image ID observation is not a resolved crabc-core-evidence digest",
    )
    paths: set[str] = set()
    source_contracts = inputs["collector_source_contracts"]
    require(isinstance(source_contracts, Mapping) and set(source_contracts) == set(SOURCE_CONTRACT_FILES), "retained collector source contract roster changed")
    for relative in SOURCE_CONTRACT_FILES:
        record = validate_retained_snapshot(
            output,
            source_contracts[relative],
            f"retained collector source {relative}",
            expected_before_path=relative,
            expected_retained_path=f"inputs/source-contracts/{relative}",
        )
        retained = record["retained"]
        assert isinstance(retained, Mapping)
        validated_descriptor_paths(
            output,
            retained,
            f"retained collector source {relative}",
            paths,
            expected_relative=f"inputs/source-contracts/{relative}",
        )

    roots = inputs["origin_roots"]
    require(isinstance(roots, Mapping) and set(roots) == ROOTED_DEPENDENCY_CLASSIFICATIONS, "retained origin-root roster changed")
    normalized_roots: dict[str, str] = {}
    for label in sorted(ROOTED_DEPENDENCY_CLASSIFICATIONS):
        normalized_roots[label] = normalized_absolute_observation(
            roots[label], f"retained origin root {label}"
        )

    compiler = inputs["compiler"]
    require(
        isinstance(compiler, Mapping)
        and set(compiler)
        == {
            "executable",
            "executable_original_path",
            "requested",
            "resource_include_original_path",
            "resource_query",
            "version",
        },
        "retained compiler input keys changed",
    )
    compiler_executable_original = normalized_absolute_observation(
        compiler["executable_original_path"], "retained compiler executable original path"
    )
    require_string(compiler["requested"], "retained compiler requested name")
    resource_include_original = normalized_absolute_observation(
        compiler["resource_include_original_path"], "retained compiler resource path"
    )
    executable = validate_retained_snapshot(
        output,
        compiler["executable"],
        "retained compiler executable",
        expected_before_path=compiler_executable_original,
        expected_retained_path="inputs/toolchain/clang",
    )
    retained = executable["retained"]
    assert isinstance(retained, Mapping)
    validated_descriptor_paths(
        output,
        retained,
        "retained compiler executable",
        paths,
        expected_relative="inputs/toolchain/clang",
    )
    tool_artifact_paths = {
        "version": {
            "stderr": "inputs/toolchain/clang-version.stderr.txt",
            "stdout": "inputs/toolchain/clang-version.stdout.txt",
        },
        "resource_query": {
            "stderr": "inputs/toolchain/clang-resource.stderr.txt",
            "stdout": "inputs/toolchain/clang-resource.stdout.txt",
        },
    }
    for label, flag in (("version", "--version"), ("resource_query", "-print-resource-dir")):
        observation = compiler[label]
        require(isinstance(observation, Mapping) and set(observation) == {"argv", "returncode", "stderr", "stdout"}, f"retained compiler {label} keys changed")
        require_strict_equal(observation["argv"], [compiler["requested"], flag], f"retained compiler {label} argv")
        require_integer(observation["returncode"], f"retained compiler {label} return code")
        require(observation["returncode"] == 0, f"retained compiler {label} failed")
        for stream in ("stdout", "stderr"):
            validated_descriptor_paths(
                output,
                observation[stream],
                f"retained compiler {label} {stream}",
                paths,
                expected_relative=tool_artifact_paths[label][stream],
            )
    retained_resource_include = retained_resource_include_from_query(output, compiler["resource_query"]["stdout"])
    require(retained_resource_include == resource_include_original, "retained compiler resource query is detached from compiler resource path")
    require(retained_resource_include == normalized_roots["compiler-resource"], "retained compiler resource query is detached from compiler-resource root")

    markers = inputs["oracle_markers"]
    require(isinstance(markers, Mapping) and set(markers) == {"linux-uapi", "pinned-musl"}, "retained oracle marker roster changed")
    marker_roots = {
        "linux-uapi": ("linux-uapi", ".crabc-linux-uapi"),
        "pinned-musl": ("pinned-musl-header-root", ".crabc-oracle"),
    }
    for label in ("linux-uapi", "pinned-musl"):
        root_label, marker_name = marker_roots[label]
        expected_marker_source = normalized_absolute_observation(
            str(Path(normalized_roots[root_label]).parent / marker_name),
            f"retained oracle marker {label} expected source",
        )
        record = validate_retained_snapshot(
            output,
            markers[label],
            f"retained oracle marker {label}",
            expected_before_path=expected_marker_source,
            expected_retained_path=f"inputs/oracle-markers/{label}",
        )
        retained = record["retained"]
        assert isinstance(retained, Mapping)
        validated_descriptor_paths(
            output,
            retained,
            f"retained oracle marker {label}",
            paths,
            expected_relative=f"inputs/oracle-markers/{label}",
        )

    dependencies = inputs["dependency_snapshots"]
    require(isinstance(dependencies, list), "retained dependency snapshots are invalid")
    dependency_keys: dict[str, Mapping[str, Any]] = {}
    dependency_origins: set[str] = set()
    for index, item in enumerate(dependencies):
        require(isinstance(item, Mapping) and set(item) == {"classification", "key", "logical_path", "original_path_observation", "snapshot"}, f"retained dependency {index} keys changed")
        classification = require_string(item["classification"], f"retained dependency {index}.classification")
        require(classification in ROOTED_DEPENDENCY_CLASSIFICATIONS | {"external-physical", "probe"}, f"retained dependency {index}.classification is invalid")
        key = require_string(item["key"], f"retained dependency {index}.key")
        safe_relative_path(key, f"retained dependency {index}.key")
        logical = safe_relative_path(item["logical_path"], f"retained dependency {index}.logical path").as_posix()
        original = normalized_absolute_observation(item["original_path_observation"], f"retained dependency {index}.original path")
        require(key not in dependency_keys and original not in dependency_origins, "retained dependency mapping is duplicated")
        if classification in ROOTED_DEPENDENCY_CLASSIFICATIONS:
            expected_original = normalized_absolute_observation(
                str(Path(normalized_roots[classification]) / logical),
                f"retained dependency {index} rooted expected path",
            )
            require(original == expected_original, f"retained dependency {index} original path is detached from {classification}")
        else:
            require(Path(original).name == logical, f"retained dependency {index} logical path is detached from original path")
        expected_key = dependency_key(classification, logical, original)
        require(key == expected_key, f"retained dependency {index}.key is not canonical")
        record = validate_retained_snapshot(
            output,
            item["snapshot"],
            f"retained dependency {index}",
            expected_before_path=original,
            expected_retained_path=f"inputs/dependencies/{key}",
        )
        retained = record["retained"]
        assert isinstance(retained, Mapping)
        validated_descriptor_paths(
            output,
            retained,
            f"retained dependency {index}",
            paths,
            expected_relative=f"inputs/dependencies/{key}",
        )
        dependency_keys[key] = item
        dependency_origins.add(original)

    selection = validate_selection_source(output, selection_source(inputs), source_contracts)
    # Each finite direct include emits its own physical PP marker.  Rebuild
    # the public `.h` roster from retained dependencies, excluding musl's
    # private `bits/` namespace exactly as the source roster does.  Equality
    # prevents a self-consistent smaller selected roster from claiming a
    # complete collection merely because omitted headers happen to be reached
    # transitively by another direct include.
    def retained_public_headers(classification: str) -> list[str]:
        headers = [
            item["logical_path"]
            for item in dependency_keys.values()
            if item["classification"] == classification
            and item["logical_path"].endswith(".h")
            and Path(item["logical_path"]).parts[0] != "bits"
        ]
        return sorted(headers)

    require_strict_equal(
        selection["candidate_headers"], retained_public_headers("candidate-header-root"),
        "retained candidate public-header dependency roster",
    )
    require_strict_equal(
        selection["pinned_headers"], retained_public_headers("pinned-musl-header-root"),
        "retained pinned-musl public-header dependency roster",
    )
    require(output_input_paths(output) == paths, "retained input files were added, removed, or renamed")
    return {"dependency_keys": dependency_keys}


def configured_oracle_exceptions(inputs: Mapping[str, Any]) -> dict[tuple[str, str], str]:
    rows = validated_oracle_exception_records(
        selection_source(inputs).get("oracle_not_applicable"), "retained oracle exception roster"
    )
    result: dict[tuple[str, str], str] = {}
    for row in rows:
        header = row["header"]
        profile = row["profile"]
        reason = row["reason"]
        require((header, profile) not in result, "retained oracle exception is duplicated")
        result[(header, profile)] = reason
    return result


def replay_job(
    *,
    output: Path,
    job: Mapping[str, Any],
    inputs: Mapping[str, Any],
    dependency_keys: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    expected_keys = {"artifacts", "dependencies", "detail", "header", "ordinal", "probe_original_path_observation", "profile", "status", "tree"}
    require(set(job) == expected_keys, "raw job keys changed")
    tree = job.get("tree")
    require(tree in {"candidate", "reference"}, "raw job tree is invalid")
    header = safe_relative_path(job.get("header"), "raw job header").as_posix()
    profile = require_string(job.get("profile"), "raw job profile")
    require_integer(job.get("ordinal"), "raw job ordinal", minimum=0)
    probe_original = require_string(job.get("probe_original_path_observation"), "raw job probe original path")
    require(Path(probe_original).is_absolute(), "raw job probe original path is not absolute")
    status = job.get("status")
    require(status in {"ok", "oracle-not-applicable"}, "raw job status is invalid")
    detail = require_string(job.get("detail"), "raw job detail", allow_empty=True)
    artifacts = job.get("artifacts")
    require(isinstance(artifacts, Mapping), "raw job artifacts are invalid")
    required_artifacts = {"ast_command", "ast_stderr", "ast_stdout", "source", "status"}
    if status == "ok":
        required_artifacts.update({"preprocessor_command", "preprocessor_stderr", "preprocessor_stdout"})
    require(set(artifacts) == required_artifacts, "raw job artifact roster changed")
    validate_job_artifact_descriptors(output, artifacts)
    status_raw = read_artifact_json(output, artifacts["status"], "raw job status artifact")
    require(isinstance(status_raw, Mapping), "raw job status artifact is invalid")
    require(set(status_raw) == {"ast_returncode", "detail", "preprocess_returncode", "schema", "status"}, "raw job status artifact keys changed")
    require(status_raw.get("schema") == RAW_ARTIFACT_SCHEMA, "raw job status artifact schema changed")
    require(status_raw.get("status") == status and status_raw.get("detail") == detail, "raw job status artifact drifted")
    require_integer(status_raw.get("ast_returncode"), "raw job AST return code")
    pre_return = status_raw.get("preprocess_returncode")
    require(pre_return is None or type(pre_return) is int, "raw job preprocessor return code is invalid")
    source_path = descriptor_path(output, artifacts["source"], "raw source")
    require(source_path.name in {"probe.c", "probe.cpp"}, "raw source name is invalid")
    require(read_artifact_text(output, artifacts["source"], "raw source") == f"#include <{header}>\n", "raw source text drifted")
    profiles = profile_by_identifier(inputs)
    profile_record = profiles.get(profile)
    require(profile_record is not None, "raw job profile is absent from retained inputs")
    validate_job_artifact_paths(
        artifacts,
        tree=tree,
        header=header,
        profile=profile_record,
        status=status,
    )
    roots = inputs["origin_roots"]
    assert isinstance(roots, Mapping)
    header_root = Path(roots["candidate-header-root"] if tree == "candidate" else roots["pinned-musl-header-root"])
    resource_root = Path(roots["compiler-resource"])
    uapi_root = Path(roots["linux-uapi"])
    compiler = inputs["compiler"]
    assert isinstance(compiler, Mapping)
    compiler_name = require_string(compiler["requested"], "retained compiler requested name")
    expected_ast_command = callable_inventory.compiler_command(
        compiler_name, profile_record, header_root, resource_root, uapi_root, Path(probe_original), ast=True, preprocess=False
    )
    ast_command = read_artifact_json(output, artifacts["ast_command"], "raw AST command")
    require_strict_equal(ast_command, expected_ast_command, "raw AST command")
    exceptions = configured_oracle_exceptions(inputs)
    exception_reason = exceptions.get((header, profile)) if tree == "reference" else None
    if status == "oracle-not-applicable":
        require(tree == "reference" and exception_reason is not None and detail == exception_reason, "oracle-not-applicable job is not the configured reference exception")
        require(status_raw["ast_returncode"] != 0 and status_raw["preprocess_returncode"] is None, "oracle-not-applicable raw status drifted")
        dependencies = job.get("dependencies")
        require(
            isinstance(dependencies, list)
            and all(isinstance(value, str) for value in dependencies)
            and len(dependencies) == 1,
            "oracle-not-applicable job must retain exactly its probe dependency",
        )
        entries = job_dependency_entries(dependencies, dependency_keys)
        require_job_probe_dependency(
            output=output,
            entries=entries,
            probe_original=probe_original,
            source_descriptor=artifacts["source"],
        )
        return {
            "occurrences": [],
            "macro_events": [],
            "final_active_macros": [],
            "summary": derived_summary([], [], []),
        }
    require(exception_reason is None, "configured oracle-not-applicable reference row was incorrectly collected as ok")
    require(status_raw["ast_returncode"] == 0 and status_raw["preprocess_returncode"] == 0, "successful raw job return codes drifted")
    ast = validate_clang_translation_unit(
        read_artifact_json(output, artifacts["ast_stdout"], "raw AST"), "raw AST"
    )
    preprocessed = read_artifact_text(output, artifacts["preprocessor_stdout"], "raw preprocessor")
    expected_preprocess_command = callable_inventory.compiler_command(
        compiler_name, profile_record, header_root, resource_root, uapi_root, Path(probe_original), ast=False, preprocess=True
    )
    preprocess_command = read_artifact_json(output, artifacts["preprocessor_command"], "raw preprocessor command")
    require_strict_equal(preprocess_command, expected_preprocess_command, "raw preprocessor command")
    derived = derive_raw_records_for_replay(
        ast_json=ast,
        preprocessed=preprocessed,
        header_root=header_root,
        tree=tree,
        input_header=header,
        profile=profile,
        raw_ast_path=artifacts["ast_stdout"]["path"],
        raw_preprocessor_path=artifacts["preprocessor_stdout"]["path"],
        source_language=profile_record.language,
    )
    expected_dependencies = dependency_keys_from_preprocessed(preprocessed, list(dependency_keys.values()))
    dependencies = job.get("dependencies")
    require(isinstance(dependencies, list) and all(isinstance(value, str) for value in dependencies), "raw job dependency keys are invalid")
    require_strict_equal(dependencies, expected_dependencies, "raw job retained dependency identities")
    entries = job_dependency_entries(dependencies, dependency_keys)
    require_job_probe_dependency(
        output=output,
        entries=entries,
        probe_original=probe_original,
        source_descriptor=artifacts["source"],
    )
    require_job_physical_origins(
        derived["occurrences"], entries, tree=tree, record_kind="declaration occurrence"
    )
    require_job_physical_origins(
        derived["macro_events"], entries, tree=tree, record_kind="macro event"
    )
    require_job_physical_origins(
        derived["final_active_macros"], entries, tree=tree, record_kind="final active macro"
    )
    return derived


def report_status(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Separate finite physical collection from conservative semantic observations."""
    unresolved = require_integer(summary.get("unresolved_linkage_occurrence_count"), "summary unresolved linkage count", minimum=0)
    return {
        "physical_occurrence_collection": "complete",
        "receipt": "raw-compiler-evidence-retained",
        "selection_closure": "not-established-by-declaration-inventory",
        "semantic_observation_status": (
            "contains-unresolved-observations" if unresolved else "all-retained-linkage-observations-known"
        ),
        "unresolved_linkage_occurrence_count": unresolved,
    }


def build_report(
    *,
    inputs: Mapping[str, Any],
    jobs: Sequence[Mapping[str, Any]],
    occurrences: Sequence[Mapping[str, Any]],
    macro_events: Sequence[Mapping[str, Any]],
    final_active_macros: Sequence[Mapping[str, Any]],
    workers: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    summary = derived_summary(occurrences, macro_events, final_active_macros)
    candidate_statuses = Counter(str(job["status"]) for job in jobs if job["tree"] == "candidate")
    reference_statuses = Counter(str(job["status"]) for job in jobs if job["tree"] == "reference")
    report = {
        "collection": {
            "candidate_job_count": sum(candidate_statuses.values()),
            "candidate_status_counts": dict(sorted(candidate_statuses.items())),
            "compiler_job_timeout_seconds": float(timeout_seconds),
            "job_count": len(jobs),
            "raw_artifact_schema": RAW_ARTIFACT_SCHEMA,
            "reference_job_count": sum(reference_statuses.values()),
            "reference_status_counts": dict(sorted(reference_statuses.items())),
            "workers": workers,
        },
        "final_active_macros": list(final_active_macros),
        "inputs": dict(inputs),
        "jobs": list(jobs),
        "macro_events": list(macro_events),
        "occurrences": list(occurrences),
        "oracle": ORACLE,
        "platform": PLATFORM,
        "schema": SCHEMA,
        "scope": {
            "compiler_ast_json": True,
            "compiler_preprocessor_records": True,
            "function_occurrences_before_collapse": True,
            "header_text_parsing": False,
            "layout_evaluation": False,
            "macro_events_before_collapse": True,
            "provider_selection": False,
            "runtime": False,
            "variable_occurrences_before_collapse": True,
        },
        "status": report_status(summary),
        "summary": summary,
        "target": TARGET,
    }
    return report


def replay_report_from_raw_evidence(
    report: Mapping[str, Any],
    *,
    output: Path,
) -> Mapping[str, Any]:
    """Reconstruct one report from retained raw files and retained inputs only."""
    require_report_keys(report)
    inputs = report["inputs"]
    require(isinstance(inputs, Mapping), "retained report inputs are invalid")
    validated_inputs = validate_retained_inputs(output, inputs)
    jobs = report["jobs"]
    expected_identities = expected_job_identities(inputs)
    require(len(jobs) == len(expected_identities), "raw job roster length changed")
    observed_identities: list[tuple[str, str, str]] = []
    for ordinal, job in enumerate(jobs):
        require(isinstance(job, Mapping), f"raw job {ordinal} is invalid")
        require(job.get("ordinal") == ordinal and type(job.get("ordinal")) is int, f"raw job {ordinal} ordinal drifted")
        observed_identities.append((job.get("tree"), job.get("header"), job.get("profile")))
    require(observed_identities == expected_identities, "raw job roster/order changed")
    expected_paths = raw_artifact_paths(jobs)
    require(output_raw_paths(output) == expected_paths, "raw artifact files were added, removed, or renamed")
    occurrences: list[dict[str, Any]] = []
    macro_events: list[dict[str, Any]] = []
    final_active: list[dict[str, Any]] = []
    observed_exceptions: set[tuple[str, str]] = set()
    dependency_keys = validated_inputs["dependency_keys"]
    assert isinstance(dependency_keys, Mapping)
    for job in jobs:
        if job["status"] == "oracle-not-applicable":
            observed_exceptions.add((job["header"], job["profile"]))
        replayed = replay_job(
            output=output,
            job=job,
            inputs=inputs,
            dependency_keys=dependency_keys,
        )
        occurrences.extend(replayed["occurrences"])
        macro_events.extend(replayed["macro_events"])
        final_active.extend(replayed["final_active_macros"])
    require(observed_exceptions == set(configured_oracle_exceptions(inputs)), "configured oracle-not-applicable rows were not represented exactly")
    expected_derived = {
        "occurrences": occurrences,
        "macro_events": macro_events,
        "final_active_macros": final_active,
        "summary": derived_summary(occurrences, macro_events, final_active),
    }
    validate_derived_records(
        {
            "occurrences": report["occurrences"],
            "macro_events": report["macro_events"],
            "final_active_macros": report["final_active_macros"],
            "summary": report["summary"],
        },
        expected_derived,
    )
    collection = report["collection"]
    require(isinstance(collection, Mapping), "report collection is invalid")
    require_integer(collection.get("workers"), "report collection workers", minimum=1)
    timeout = collection.get("compiler_job_timeout_seconds")
    require(type(timeout) is float and timeout > 0 and math.isfinite(timeout), "report collection timeout is invalid")
    expected_collection = build_report(
        inputs=inputs,
        jobs=jobs,
        occurrences=occurrences,
        macro_events=macro_events,
        final_active_macros=final_active,
        workers=collection["workers"],
        timeout_seconds=timeout,
    )["collection"]
    require_strict_equal(collection, expected_collection, "report collection summary")
    require_strict_equal(report["status"], report_status(expected_derived["summary"]), "report status")
    return report


def validate_report(
    report_path: Path,
    *,
    project_include: Path = ROOT / "include",
) -> Mapping[str, Any]:
    """Pure host replay with a separately reported current selecting-source seal.

    No compiler is executed and no original `/opt` oracle or source path is
    opened.  Missing or changed retained inputs hard-fail.  Current source
    drift is returned as an explicit historical-measurement fact so a selector
    can refuse same-source closure without losing the replayed report.
    """
    report_path = report_path if report_path.is_absolute() else ROOT / report_path
    output = existing_evidence_directory(report_path)
    report = load_json_object(report_path, "declaration inventory report")
    replayed = replay_report_from_raw_evidence(report, output=output)
    current = current_selecting_source_status(replayed["inputs"], project_include)
    return {"current_selecting_source": current, "report": replayed}


def validation_result(report_path: Path, envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Render the small host-replay receipt without duplicating raw evidence."""
    require(isinstance(envelope, Mapping) and set(envelope) == {"current_selecting_source", "report"}, "validation envelope is invalid")
    report = envelope["report"]
    current = envelope["current_selecting_source"]
    require(isinstance(report, Mapping), "validation report is invalid")
    require(isinstance(current, Mapping) and set(current) == {"differences", "matches_retained"}, "validation current selecting-source status is invalid")
    require_boolean(current["matches_retained"], "validation current selecting-source match")
    require(isinstance(current["differences"], list), "validation current selecting-source differences are invalid")
    report_path = report_path if report_path.is_absolute() else ROOT / report_path
    return {
        "current_selecting_source": current,
        "report": {
            "path": str(report_path.resolve()),
            "schema": report.get("schema"),
            "sha256": sha256_file(report_path),
            "status": report.get("status"),
            "summary": report.get("summary"),
        },
        "schema": VALIDATION_SCHEMA,
    }


def collect_report(
    *,
    output: Path,
    compiler: str,
    project_include: Path,
    musl_include: Path,
    linux_uapi_include: Path,
    workers: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    output = physical_output_directory(output)
    try:
        live, contract, resource_include, candidate_headers, pinned_headers = collection_inputs(
            compiler=compiler,
            project_include=project_include,
            musl_include=musl_include,
            linux_uapi_include=linux_uapi_include,
        )
        source_contracts = snapshot_source_contracts(output)
        tool_observations = snapshot_tool_observations(output, live)
        oracle_markers = snapshot_oracle_markers(output, live)
        jobs, occurrences, macro_events, final_active_macros = collect_raw_jobs(
            output=output,
            compiler=compiler,
            contract=contract,
            resource_include=resource_include,
            project_include=project_include,
            musl_include=musl_include,
            linux_uapi_include=linux_uapi_include,
            candidate_headers=candidate_headers,
            pinned_headers=pinned_headers,
            workers=workers,
            timeout_seconds=timeout_seconds,
        )
        inputs = retained_inputs(
            output=output,
            live=live,
            source_contracts=source_contracts,
            oracle_markers=oracle_markers,
            tool_observations=tool_observations,
            jobs=jobs,
            project_include=project_include,
        )
        report = build_report(
            inputs=inputs,
            jobs=jobs,
            occurrences=occurrences,
            macro_events=macro_events,
            final_active_macros=final_active_macros,
            workers=workers,
            timeout_seconds=timeout_seconds,
        )
        write_json(output / "report.json", report)
        return report
    except BaseException:
        print(
            f"x86 header declaration inventory: retained raw collection at {output.relative_to(ROOT)}",
            file=sys.stderr,
        )
        raise


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--collect", action="store_true", help="collect a fresh raw finite header roster")
    mode.add_argument("--validate-report", type=Path, metavar="REPORT", help="replay one retained report from raw evidence")
    parser.add_argument("--output", type=Path, help="fresh evidence directory below .work/x86_64/header-declaration-inventory")
    parser.add_argument("--compiler")
    parser.add_argument("--project-include", type=Path)
    parser.add_argument("--musl-include", type=Path)
    parser.add_argument("--linux-uapi-include", type=Path)
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help=f"bounded concurrent compiler jobs (1 through {abi_matrix.MAX_COLLECTION_WORKERS})",
    )
    parser.add_argument("--timeout-seconds", type=float)
    parsed = parser.parse_args(arguments)
    if parsed.collect:
        require(parsed.output is not None, "--collect requires --output")
        collect_report(
            output=parsed.output,
            compiler=parsed.compiler or "clang",
            project_include=parsed.project_include or ROOT / "include",
            musl_include=parsed.musl_include or Path("/opt/musl-1.2.6/include"),
            linux_uapi_include=parsed.linux_uapi_include or Path("/opt/linux-5.10-uapi/include"),
            workers=parsed.workers if parsed.workers is not None else DEFAULT_WORKERS,
            timeout_seconds=(
                parsed.timeout_seconds
                if parsed.timeout_seconds is not None
                else DEFAULT_TIMEOUT_SECONDS
            ),
        )
    else:
        require(parsed.output is None, "--output only applies to --collect")
        require(parsed.compiler is None, "--compiler only applies to --collect")
        require(parsed.project_include is None, "--project-include only applies to --collect; use the current checkout for host replay")
        require(parsed.musl_include is None, "--musl-include only applies to --collect")
        require(parsed.linux_uapi_include is None, "--linux-uapi-include only applies to --collect")
        require(parsed.workers is None, "--workers only applies to --collect")
        require(parsed.timeout_seconds is None, "--timeout-seconds only applies to --collect")
        envelope = validate_report(
            parsed.validate_report,
        )
        print(canonical_json(validation_result(parsed.validate_report, envelope)), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HeaderDeclarationInventoryError as error:
        print(f"header declaration inventory: {error}", file=sys.stderr)
        raise SystemExit(2)
