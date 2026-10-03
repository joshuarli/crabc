#!/usr/bin/env python3
"""Read finite native compiler-helper archive ownership evidence.

This component owns the producer contract for the Rust-only x86 helper archive
and its exact private copy linked into owned libc.so. It does not turn an
archive definition into a public runtime export. A later collector supplies
fresh, source-matched product and complete-ELF receipts to the helpers below.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
from typing import Any, Mapping, Sequence

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
from loader_debug_abi_evidence import Elf, EvidenceError

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = Path("builtins/x86_64-helper-contract.toml")
SOURCE = Path("builtins/src/lib.rs")
BUILDER = Path("builtins/build_x86_64.py")
DYNAMIC_BUILDER = Path("scripts/build_x86_64_owned_dynamic_sysroot.py")
DYNAMIC_QUALIFICATION = Path("compat/x86_64/owned_dynamic_qualification.py")
AGGREGATE_PROBE = Path("builtins/fixtures/x86_64_compiler_helper_aggregate_probe.c")
AGGREGATE_START = Path("builtins/fixtures/x86_64_compiler_helper_aggregate_start.S")
AGGREGATE_RUNNER = Path("builtins/run_x86_64_compiler_helper_aggregate.sh")
SHARED_PLACEMENT_RUNNER = Path("builtins/run_x86_64_compiler_helper_shared_placement.sh")
SHARED_PLACEMENT_FIXTURES = (
    Path("builtins/fixtures/x86_64_compiler_helper_shared_direct.c"),
    Path("builtins/fixtures/x86_64_compiler_helper_shared_dso.c"),
    Path("builtins/fixtures/x86_64_compiler_helper_shared_dso_consumer.c"),
    Path("builtins/fixtures/x86_64_compiler_helper_shared_interpose.c"),
)
SELECTION = Path("compat/x86_64/native-abi-selection.toml")
READER = Path("compat/x86_64/compiler_helper_evidence.py")
DOCUMENTATION = Path("builtins/x86_64-helper-contract.md")
BUILTINS_DOCUMENTATION = Path("builtins/README.md")
MATERIALIZED_DYNAMIC_DOCUMENTATION = Path("compat/x86_64/materialized-dynamic-sysroot.md")
SELECTION_DOCUMENTATION = Path("compat/x86_64/native-abi-selection.md")
ELF_READER = Path("compat/x86_64/loader_debug_abi_evidence.py")
CAST_PROBE = Path("builtins/fixtures/x86_64_int128_casts_probe.c")
BINARY32_CAST_PROBE = Path("builtins/fixtures/x86_64_binary32_casts_probe.c")
SOURCE_FILES = (*(Path("builtins/fixtures/llvm22_float_complex") / name for name in
                  ("mulsc3.c", "divsc3.c", "LICENSE.TXT", "SHA256SUMS")),
                Path("builtins/fixtures/x86_64_float_complex_probe.c"), Path("builtins/fixtures/x86_64_float_complex_differential.c"),
                *(Path("builtins/fixtures/llvm22_divdc3") / name for name in
                  ("int_lib.h", "int_math.h", "int_types.h", "int_endianness.h", "int_util.h", "fp_lib.h", "divdc3.c", "LICENSE.TXT", "SHA256SUMS")),
                Path("builtins/src/x86_64_binary80.S"), Path("builtins/generate_x86_64_binary80.py"),
                Path("builtins/fixtures/x86_64_binary80_probe.c"), Path("builtins/fixtures/x86_64_binary80_differential.c"),
                *(Path("builtins/fixtures/llvm22_binary80") / name for name in
                  ("floattixf.c", "floatuntixf.c", "fixxfti.c", "fixunsxfti.c", "mulxc3.c", "divxc3.c", "LICENSE.TXT", "SHA256SUMS")),
                *(Path("builtins/fixtures/musl126_binary80") / name for name in
                  ("fmaxl.c", "logbl.c", "ilogbl.c", "scalbnl.c", "__fpclassifyl.c", "__signbitl.c", "COPYRIGHT", "SHA256SUMS")),
                CAST_PROBE, BINARY32_CAST_PROBE, CONTRACT, SOURCE, Path("builtins/src/x86_64_complex_classification.rs"), BUILDER, DYNAMIC_BUILDER, DYNAMIC_QUALIFICATION, AGGREGATE_PROBE, AGGREGATE_START, AGGREGATE_RUNNER,
                SHARED_PLACEMENT_RUNNER, *SHARED_PLACEMENT_FIXTURES, READER, SELECTION, DOCUMENTATION,
                BUILTINS_DOCUMENTATION, MATERIALIZED_DYNAMIC_DOCUMENTATION, SELECTION_DOCUMENTATION, ELF_READER)
SCHEMA = "crabc.x86_64-compiler-helper-owner/v1"
AGGREGATE_SCHEMA = "crabc.x86_64-compiler-helper-aggregate/v1"
SOURCE_SEAL_SCHEMA = "crabc.x86_64-compiler-helper-source-seal/v1"
TARGET = "x86_64-unknown-linux-musl"
ARCHIVE_PLACEMENTS = ("static-builtins", "dynamic-builtins")
ARCHIVE_MEMBER = "crabc-builtins.o"
HELPER_METADATA = {
    "type": "FUNC", "binding": "GLOBAL", "visibility": "DEFAULT",
    "version": None, "version_default": False,
}
SHARED_LIBC_METADATA = {
    "artifact": "candidate-shared",
    "linker_option": "--exclude-libs=libcrabc-builtins.a",
    "type": "FUNC",
    "binding": "LOCAL",
    "visibility": "DEFAULT",
    "dynsym": False,
}
HELPER_ABIS = {
    "u128-to-binary64", "binary64-to-u128", "u128-to-binary32", "binary32-to-u128",
    "i128-to-binary80", "u128-to-binary80", "binary80-to-i128", "binary80-to-u128", "complex-binary80",
    "complex-float", "complex-double", "u128-binary", "u128-bit-count", "u128-byte-swap",
    "u128-divmod-slot", "u128-overflow-slot", "u128-shift", "u32-byte-swap",
    "u64-bit-count", "u64-byte-swap",
}


class CompilerHelperEvidenceError(ValueError):
    """A finite compiler-helper receipt or source contract is not exact."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CompilerHelperEvidenceError(message)


def same(left: object, right: object) -> bool:
    """Compare JSON values without treating booleans as integers."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def digest(path: Path) -> str:
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), f"source is not a physical regular file: {path}")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def file_identity(root: Path, relative: Path) -> dict[str, Any]:
    root, relative = Path(root).absolute(), Path(relative)
    require(not relative.is_absolute() and ".." not in relative.parts and relative.parts,
            "source path escapes checkout")
    path = root / relative
    require(path.is_file() and not path.is_symlink() and path.resolve() == path,
            f"source is not a physical regular file: {relative}")
    return {"path": relative.as_posix(), "sha256": digest(path), "size": path.stat().st_size}


def _read_toml(root: Path) -> dict[str, Any]:
    path = Path(root).absolute() / CONTRACT
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise CompilerHelperEvidenceError("compiler-helper producer contract is unreadable") from error
    require(type(value) is dict, "compiler-helper producer contract is not an object")
    return value


def _helper_metadata(value: object) -> dict[str, Any]:
    require(type(value) is dict and set(value) == {"type", "binding", "visibility", "version", "version_default"},
            "compiler-helper metadata fields differ")
    require((type(value["version"]) is str and value["version"] == "unversioned") or value["version"] is None,
            "compiler-helper version differs")
    normalized = {**value, "version": None}
    require(same(normalized, HELPER_METADATA), "compiler-helper metadata differs")
    return dict(HELPER_METADATA)


def validate_contract(value: object, *, root: Path = ROOT) -> dict[str, Any]:
    """Validate exact finite source ownership, never infer a prefix roster."""

    require(type(value) is dict and set(value) == {
        "schema", "target", "owner_group", "source", "builder", "producer_scope", "archive", "shared_libc", "helpers",
    }, "compiler-helper contract fields differ")
    require(type(value["schema"]) is int and value["schema"] == 1 and value["target"] == TARGET,
            "compiler-helper contract schema/target differs")
    require(value["owner_group"] == "owned-compiler-helper-archive" and value["source"] == SOURCE.as_posix()
            and value["builder"] == BUILDER.as_posix() and type(value["producer_scope"]) is str
            and value["producer_scope"], "compiler-helper owner source differs")
    archive = value["archive"]
    require(type(archive) is dict and set(archive) == {"name", "member", "placements"},
            "compiler-helper archive fields differ")
    require(archive["name"] == "libcrabc-builtins.a" and archive["member"] == ARCHIVE_MEMBER
            and archive["placements"] == list(ARCHIVE_PLACEMENTS), "compiler-helper archive placements differ")
    require(same(value["shared_libc"], SHARED_LIBC_METADATA),
            "compiler-helper shared-libc placement differs")
    helpers = value["helpers"]
    require(type(helpers) is list and bool(helpers), "compiler-helper helper roster differs")
    result: list[dict[str, Any]] = []
    names: list[str] = []
    for row in helpers:
        require(type(row) is dict and set(row) == {"name", "source_definition", "c_abi", "caller_obligation", "metadata"},
                "compiler-helper helper record differs")
        name, definition, c_abi, obligation = row["name"], row["source_definition"], row["c_abi"], row["caller_obligation"]
        require(type(name) is str and re.fullmatch(r"__[a-z0-9]+", name) is not None,
                "compiler-helper name differs")
        require(type(definition) is str and ((definition.startswith('pub ') and f"fn {name}" in definition) or definition == f".globl {name}; .type {name},@function"),
                "compiler-helper source definition differs")
        require(type(c_abi) is str and c_abi in HELPER_ABIS and type(obligation) is str and obligation,
                "compiler-helper C ABI role differs")
        result.append({"name": name, "source_definition": definition, "c_abi": c_abi,
                       "caller_obligation": obligation, "metadata": _helper_metadata(row["metadata"])})
        names.append(name)
    require(names == sorted(names) and len(names) == len(set(names)) and set(names) == set(source_definitions(root)), "compiler-helper helper roster differs")
    return {"schema": 1, "target": TARGET, "owner_group": value["owner_group"], "source": value["source"],
            "builder": value["builder"], "producer_scope": value["producer_scope"], "archive": dict(archive),
            "shared_libc": dict(SHARED_LIBC_METADATA), "helpers": result}


def load_contract(root: Path = ROOT) -> dict[str, Any]:
    raw = _read_toml(root)
    helpers = raw.get("helpers") if type(raw) is dict else None
    require(type(helpers) is list and all(type(row) is dict and type(row.get("metadata")) is dict
            and row["metadata"].get("version") == "unversioned" for row in helpers),
            "compiler-helper producer contract must spell unversioned metadata")
    return validate_contract(raw, root=root)


def helper_names(contract: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(row["name"] for row in contract["helpers"])


def source_definitions(root: Path = ROOT) -> dict[str, str]:
    """Read Rust C definitions and the included binary80 assembly exports."""

    path = Path(root).absolute() / SOURCE
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise CompilerHelperEvidenceError("compiler-helper Rust source is unreadable") from error
    pattern = re.compile(r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(__\w+)\s*\((.*?)\)\s*->\s*([\w:<>]+)', re.S)
    result: dict[str, str] = {}
    for match in pattern.finditer(text):
        name = match.group(1)
        require(name not in result, f"duplicate compiler-helper source definition: {name}")
        result[name] = " ".join(match.group(0).split())
    if 'include_str!("x86_64_binary80.S")' in text:
        assembly = path.with_name("x86_64_binary80.S").read_text()
        for name in re.findall(r'^\s*\.globl\s+(__\w+)\s*$', assembly, re.M):
            require(re.search(r'^\s*\.type\s+' + re.escape(name) + r',\s*@function\s*$', assembly, re.M) is not None,
                    "assembly export lacks function type: " + name)
            require(name not in result, "duplicate assembly helper: " + name)
            result[name] = ".globl " + name + "; .type " + name + ",@function"
    return result


def source_binding(root: Path, contract: Mapping[str, Any] | None = None) -> dict[str, Any]:
    root = Path(root).absolute()
    contract = load_contract(root) if contract is None else validate_contract(dict(contract), root=root)
    expected = {row["name"]: row["source_definition"] for row in contract["helpers"]}
    require(source_definitions(root) == expected, "compiler-helper source definitions differ from contract")
    files = [file_identity(root, path) for path in SOURCE_FILES]
    return {"files": files, "helper_names": list(helper_names(contract)), "target": TARGET}


def _archive_member_rows(facts: object, placement: str, contract: Mapping[str, Any]) -> dict[str, Any]:
    require(type(facts) is dict and placement in facts, f"compiler-helper {placement} facts are absent")
    members = facts[placement]
    require(type(members) is list and len(members) == 1, f"compiler-helper {placement} member roster differs")
    member = members[0]
    require(type(member) is dict and member.get("member") == contract["archive"]["member"]
            and member.get("member_index") == 0 and member.get("member_occurrence") == 0,
            f"compiler-helper {placement} member differs")
    tables = member.get("symbol_tables")
    require(type(tables) is list and len(tables) == 1 and tables[0].get("name") == ".symtab",
            f"compiler-helper {placement} symbol table differs")
    rows = tables[0].get("rows")
    require(type(rows) is list, f"compiler-helper {placement} symbols differ")
    expected = set(helper_names(contract))
    definitions = [row for row in rows if isinstance(row, dict) and row.get("name") in expected]
    require(len(definitions) == len(expected) and {row["name"] for row in definitions} == expected,
            f"compiler-helper {placement} helper roster differs")
    sections = {str(section.get("index")): section for section in member.get("sections", []) if isinstance(section, dict)}
    result: dict[str, Any] = {}
    for row in definitions:
        observed = {key: row.get(key) for key in HELPER_METADATA}
        require(same(observed, HELPER_METADATA), f"compiler-helper {placement} metadata differs")
        section_index = row.get("section_index")
        section = sections.get(section_index)
        require(type(section_index) is str and section_index not in {"UND", "ABS"} and isinstance(section, dict)
                and section.get("name") == ".text." + row["name"] and "X" in section.get("flags", ""),
                f"compiler-helper {placement} defining section differs")
        result[row["name"]] = {"member": contract["archive"]["member"], "section": section["name"],
                                "metadata": dict(HELPER_METADATA)}
    exported_functions = [row for row in rows if isinstance(row, dict) and row.get("section_index") not in {"UND", "ABS"}
                          and row.get("type") == "FUNC" and row.get("binding") == "GLOBAL"
                          and row.get("visibility") == "DEFAULT"]
    require({row.get("name") for row in exported_functions} == expected and len(exported_functions) == len(expected),
            f"compiler-helper {placement} exported function roster differs")
    return result


def archive_placements_from_elf_facts(facts_report: Mapping[str, Any], contract: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the two selected archive placements without examining shared libc."""

    require(isinstance(facts_report, Mapping) and facts_report.get("target") == TARGET,
            "complete ELF facts target differs")
    facts = facts_report.get("facts")
    result = {placement: _archive_member_rows(facts, placement, contract) for placement in ARCHIVE_PLACEMENTS}
    require(set(result["static-builtins"]) == set(result["dynamic-builtins"]) == set(helper_names(contract)),
            "compiler-helper archive placements differ")
    return result


def shared_libc_placement_from_elf_facts(
    facts_report: Mapping[str, Any], contract: Mapping[str, Any]
) -> dict[str, Any]:
    """Project the exact private libc copy from complete-ELF artifact facts.

    The complete-ELF reader represents an ELF artifact as one object containing
    ``sections`` and ``symbol_tables``.  This is deliberately unlike archive
    placements, which are lists of member objects.  Keeping the distinction
    here prevents an equally named archive definition from standing in for the
    local copy linked into libc.so.
    """

    require(isinstance(facts_report, Mapping) and facts_report.get("target") == TARGET,
            "complete ELF facts target differs")
    facts = facts_report.get("facts")
    shared = facts.get("candidate-shared") if isinstance(facts, Mapping) else None
    require(type(shared) is dict, "compiler-helper candidate-shared facts are absent")
    tables = shared.get("symbol_tables")
    sections = shared.get("sections")
    require(type(tables) is list and type(sections) is list,
            "compiler-helper candidate-shared artifact facts differ")
    by_name = {table.get("name"): table for table in tables if isinstance(table, dict)}
    require(len(tables) == 2 and set(by_name) == {".dynsym", ".symtab"},
            "compiler-helper candidate-shared symbol tables differ")
    section_by_index = {section.get("index"): section for section in sections if isinstance(section, dict)}
    require(len(section_by_index) == len(sections), "compiler-helper candidate-shared sections differ")
    expected = set(helper_names(contract))
    dynamic = by_name[".dynsym"].get("rows")
    full = by_name[".symtab"].get("rows")
    require(type(dynamic) is list and type(full) is list, "compiler-helper candidate-shared symbols differ")
    require(not any(isinstance(row, dict) and row.get("name") in expected for row in dynamic),
            "compiler-helper private libc copy leaked into dynsym")
    local = [row for row in full if isinstance(row, dict) and row.get("name") in expected]
    require(len(local) == len(expected) and {row["name"] for row in local} == expected,
            "compiler-helper private libc symtab roster differs")
    metadata = {key: contract["shared_libc"][key] for key in ("type", "binding", "visibility")}
    result: dict[str, Any] = {}
    for row in local:
        observed = {key: row.get(key) for key in metadata}
        section_index = row.get("section_index")
        section_number = int(section_index) if type(section_index) is str and re.fullmatch(r"[1-9][0-9]*", section_index) else None
        section = section_by_index.get(section_number)
        require(same(observed, metadata) and row.get("version") is None and row.get("version_default") is False
                and type(row.get("row_index")) is int and row["row_index"] >= 0
                and isinstance(section, dict) and section.get("index") == section_number
                and type(section.get("name")) is str and section["name"]
                and type(section.get("flags")) is str and "X" in section["flags"],
                "compiler-helper private libc symtab metadata differs")
        result[row["name"]] = {"table": ".symtab", "row_index": row["row_index"],
                               "section_index": section_number, "section": section["name"],
                               "metadata": dict(metadata)}
    return result


def _installed_archive_identities(facts_report: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Read both installed archive identities authenticated by complete facts."""

    artifacts = facts_report.get("artifacts") if isinstance(facts_report, Mapping) else None
    require(type(artifacts) is dict and set(ARCHIVE_PLACEMENTS) <= set(artifacts),
            "complete ELF archive placement identities are absent")
    result: dict[str, dict[str, Any]] = {}
    for placement in ARCHIVE_PLACEMENTS:
        record = artifacts[placement]
        require(type(record) is dict and type(record.get("identity")) is dict,
                f"complete ELF {placement} artifact identity differs")
        identity = record["identity"]
        require(type(identity.get("path")) is str and identity["path"]
                and type(identity.get("sha256")) is str
                and re.fullmatch(r"[0-9a-f]{64}", identity["sha256"]) is not None
                and type(identity.get("size")) is int and identity["size"] > 0,
                f"complete ELF {placement} archive identity differs")
        result[placement] = {"path": identity["path"], "sha256": identity["sha256"], "size": identity["size"]}
    require(result["static-builtins"]["path"] != result["dynamic-builtins"]["path"],
            "complete ELF archive placements do not retain distinct physical paths")
    return result


def shared_libc_archive_policy_from_product(
    provenance: Mapping[str, Any], manifest: Mapping[str, Any],
    facts_report: Mapping[str, Any], *, root: Path = ROOT,
) -> dict[str, Any]:
    """Authenticate the one archive exclusion alongside another libc owner.

    The caller has replayed the owning dynamic product and complete ELF facts.
    Join its source policy, exact link input, installed archive bytes, archive
    definitions and private libc copy without replaying those larger receipts.
    This grants no exclusion policy to an allocator archive or another owner.
    """
    contract = load_contract(root)
    identity = file_identity(root, CONTRACT)
    expected = {
        "source": {"path": identity["path"], "sha256": identity["sha256"],
                   "mode": (Path(root) / CONTRACT).stat().st_mode & 0o777},
        "archive": contract["archive"]["name"], "member": contract["archive"]["member"],
        **contract["shared_libc"],
    }
    require(isinstance(provenance, Mapping)
            and same(provenance.get("shared_compiler_helper_archive"), expected),
            "compiler-helper shared archive source policy differs")
    command = provenance.get("libc_shared_link_command")
    require(type(command) is list and all(type(item) is str for item in command),
            "compiler-helper shared link command differs")
    require([item for item in command if "--exclude-libs" in item] == [expected["linker_option"]],
            "compiler-helper shared archive exclusion differs")
    require([item for item in command if not item.startswith("-") and item.endswith(".a")]
            == ["$BUILD/" + expected["archive"]],
            "compiler-helper shared archive link input differs")
    archives = _installed_archive_identities(facts_report)
    installed = archives["dynamic-builtins"]
    files = manifest.get("files") if isinstance(manifest, Mapping) else None
    require(isinstance(files, Mapping)
            and files.get("usr/lib/" + expected["archive"]) == installed["sha256"],
            "compiler-helper shared archive manifest identity differs")
    placements = archive_placements_from_elf_facts(facts_report, contract)
    private = shared_libc_placement_from_elf_facts(facts_report, contract)
    return {"policy": expected, "installed_archive": installed,
            "archive_placements": placements, "private_libc_copy": private}


def _aggregate_archive_join(root: Path, aggregate_report: Path, *, supplied_source: Mapping[str, Any],
                            installed_archives: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Attach C ABI proof only when both installed archives have its exact bytes."""

    aggregate_report = _physical_file(aggregate_report, "compiler-helper aggregate report")
    require(aggregate_report.is_relative_to(Path(root).absolute() / ".work"),
            "compiler-helper aggregate report is outside checkout work")
    aggregate = validate_aggregate_report(aggregate_report, root=Path(root).absolute())
    expected_source = aggregate.get("product_source_after")
    require(same(aggregate.get("product_source_before"), supplied_source)
            and same(expected_source, supplied_source),
            "compiler-helper aggregate and supplied products use different source identities")
    archive = aggregate.get("artifacts", {}).get("libcrabc-builtins.a") if type(aggregate.get("artifacts")) is dict else None
    require(type(archive) is dict and type(archive.get("sha256")) is str
            and re.fullmatch(r"[0-9a-f]{64}", archive["sha256"]) is not None
            and type(archive.get("size")) is int and archive["size"] > 0,
            "compiler-helper aggregate archive identity differs")
    for placement in ARCHIVE_PLACEMENTS:
        installed = installed_archives.get(placement)
        require(type(installed) is dict and installed.get("sha256") == archive["sha256"]
                and installed.get("size") == archive["size"],
                f"compiler-helper aggregate archive differs from installed {placement}")
    return {"aggregate_report": {
        "path": aggregate_report.relative_to(root).as_posix(), "sha256": digest(aggregate_report),
        "size": aggregate_report.stat().st_size, "mode": aggregate_report.stat().st_mode & 0o777,
    }, "source": dict(supplied_source), "archive": {"sha256": archive["sha256"], "size": archive["size"]},
        "installed_archives": {placement: dict(installed_archives[placement]) for placement in ARCHIVE_PLACEMENTS},
        "c_abi_proof": "aggregate-direct-c-consumer"}


def account_compiler_helpers(validated_receipt: Mapping[str, Any], selected_owner_group: Mapping[str, Any],
                             complete_occurrences: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Return only source-selected archive placement accounting.

    The caller supplies selection records from the native selection engine. This
    function deliberately leaves candidate-shared rows out: archive selection
    does not imply a shared-libc visibility decision.
    """

    contract = validate_contract(validated_receipt["contract"])
    names = set(helper_names(contract))
    require(selected_owner_group.get("id") == contract["owner_group"]
            and selected_owner_group.get("artifacts") == list(ARCHIVE_PLACEMENTS)
            and set(selected_owner_group.get("members", ())) == names,
            "compiler-helper selected owner group differs")
    by_name: dict[str, list[Mapping[str, Any]]] = {name: [] for name in names}
    for occurrence in complete_occurrences:
        if occurrence.get("row", {}).get("name") in names:
            by_name[occurrence["row"]["name"]].append(occurrence)
    for name, rows in by_name.items():
        selected = [row for row in rows if row.get("artifact_key") in ARCHIVE_PLACEMENTS and row.get("role") == "definition"]
        require(len(selected) == 2, f"compiler-helper {name} selected archive occurrence differs")
        require({row["artifact_key"] for row in selected} == set(ARCHIVE_PLACEMENTS),
                f"compiler-helper {name} selected archive placement differs")
    return {"owner_group": contract["owner_group"], "placements": list(ARCHIVE_PLACEMENTS),
            "names": list(helper_names(contract)), "shared_placement_selected": False,
            "family_completion": False, "public_support": False}


def write_fixture_report(output: Path, *, contract: Mapping[str, Any], source: Mapping[str, Any]) -> dict[str, Any]:
    """Write a source-only fixture receipt used to prove writer/reader identity.

    This is intentionally not product, ELF, C ABI, or qualification evidence.
    It exists so a producer schema change cannot be accepted without exercising
    the corresponding reader before a later supplied-product collection.
    """

    contract = validate_contract(dict(contract))
    source = source_binding(ROOT, contract) if source is None else dict(source)
    report = {"schema": SCHEMA, "kind": "source-only-writer-reader-control", "contract": contract,
              "source": source, "archive": {"member": contract["archive"]["member"],
              "placements": list(ARCHIVE_PLACEMENTS)}, "product_collection": False,
              "family_completion": False, "public_support": False}
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), "fixture report output already exists")
    output.write_text(canonical_json(report), encoding="utf-8")
    return report


def validate_fixture_report(report_path: Path, *, root: Path = ROOT) -> dict[str, Any]:
    report_path = Path(report_path)
    require(report_path.is_file() and not report_path.is_symlink(), "fixture report is not physical")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CompilerHelperEvidenceError("fixture report is unreadable") from error
    require(type(report) is dict and set(report) == {"schema", "kind", "contract", "source", "archive", "product_collection", "family_completion", "public_support"},
            "fixture report fields differ")
    require(report["schema"] == SCHEMA and report["kind"] == "source-only-writer-reader-control"
            and type(report["product_collection"]) is bool and report["product_collection"] is False
            and type(report["family_completion"]) is bool and report["family_completion"] is False
            and type(report["public_support"]) is bool and report["public_support"] is False,
            "fixture report boundary differs")
    contract = validate_contract(report["contract"])
    require(same(report["archive"], {"member": ARCHIVE_MEMBER, "placements": list(ARCHIVE_PLACEMENTS)}),
            "fixture report archive member differs")
    require(same(report["source"], source_binding(root, contract)), "fixture report source differs")
    return report




def _load_companion_modules():
    """Import only the existing finite product readers when product inputs exist."""

    module_dir = Path(__file__).resolve().parent
    if str(module_dir) not in sys.path:
        sys.path.insert(0, str(module_dir))
    import native_abi_elf_facts as elf_facts
    import public_data_ordinary_link_evidence as ordinary_link
    return elf_facts, ordinary_link


def _archive_object_bytes(archive: Path, member: str) -> bytes:
    """Read one physical archive member without admitting a duplicate name."""

    listed = subprocess.run(("/usr/bin/ar", "t", str(archive)), capture_output=True, check=False)
    require(listed.returncode == 0 and listed.stderr == b""
            and listed.stdout.decode("ascii").splitlines().count(member) == 1,
            "ordinary import archive member is absent or duplicated")
    extracted = subprocess.run(("/usr/bin/ar", "p", str(archive), member), capture_output=True, check=False)
    require(extracted.returncode == 0 and extracted.stderr == b"" and extracted.stdout,
            "ordinary import archive member could not be read")
    return extracted.stdout


def _elf_section_name(elf: Elf, index: int) -> str:
    names_index = elf.unpack("<H", 62)[0]
    require(0 <= names_index < len(elf.sections) and 0 <= index < len(elf.sections),
            "ordinary import ELF section index differs")
    names = elf.sections[names_index]
    section = elf.sections[index]
    start = names[4] + section[0]
    limit = names[4] + names[5]
    require(names[1] == 3 and start < limit <= len(elf.data),
            "ordinary import ELF section strings differ")
    end = elf.data.find(b"\0", start, limit)
    require(end > start, "ordinary import ELF section name differs")
    return elf.data[start:end].decode("ascii")


def _direct_source_calls(object_bytes: bytes, name: str, work: Path, *,
                         allow_tail_calls: bool = False) -> list[dict[str, Any]]:
    """Read every direct call relocation from the authenticated C object."""

    scratch = work / ".work/x86_64/tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch) as temporary:
        path = Path(temporary) / "importer.o"
        path.write_bytes(object_bytes)
        elf = Elf(path)
    require(elf.elf_type == 1, "ordinary import source is not relocatable ELF")
    calls: list[dict[str, Any]] = []
    for relocations in elf.sections:
        if relocations[1] != 4:
            continue
        require(relocations[9] == 24 and relocations[5] % 24 == 0,
                "ordinary import relocation section differs")
        target_index = relocations[7]
        require(target_index < len(elf.sections), "ordinary import relocation target differs")
        target = elf.sections[target_index]
        section = _elf_section_name(elf, target_index)
        for offset in range(0, relocations[5], 24):
            destination, info, addend = elf.unpack("<QQq", relocations[4] + offset)
            symbol = elf.symbol_row(relocations[6], info >> 32)
            if symbol["name"] != name:
                continue
            require(symbol["section"] == 0 and symbol["binding"] == "GLOBAL"
                    and info & 0xffffffff == 4 and addend == -4
                    and (section.startswith(".text.") or (allow_tail_calls and section == ".text")) and target[1] == 1
                    and 1 <= destination and destination + 4 <= target[5]
                    and target[4] + destination + 4 <= len(elf.data)
                    and elf.data[target[4] + destination - 1] in ({0xe8, 0xe9} if allow_tail_calls else {0xe8}),
                    "ordinary import source is not a direct C call")
            calls.append({"section": section, "offset": destination,
                          **({"opcode": elf.data[target[4] + destination - 1]} if allow_tail_calls else {})})
    require(calls and len({(row["section"], row["offset"]) for row in calls}) == len(calls),
            "ordinary import source call roster differs")
    return calls


def _virtual_instruction(elf: Elf, address: int) -> bytes:
    matches = [elf.data[program[2] + address - program[3]:program[2] + address - program[3] + 5]
               for program in elf.programs if program[0] == 1 and program[1] & 1
               and program[3] <= address and address + 5 <= program[3] + program[5]]
    require(len(matches) == 1 and len(matches[0]) == 5,
            "ordinary import final call is outside one executable load segment")
    return matches[0]


def _final_direct_calls(elf: Elf, source_calls: Sequence[Mapping[str, Any]],
                        source_addresses: Mapping[str, tuple[int, int]],
                        provider_address: int) -> dict[str, Any]:
    """Resolve surviving source relocations through final ELF call bytes."""

    resolved = []
    discarded = []
    for source in source_calls:
        section, offset = source["section"], source["offset"]
        placement = source_addresses.get(section)
        if placement is None:
            discarded.append(dict(source))
            continue
        start, size = placement
        require(type(start) is int and type(size) is int and start > 0 and size > 0
                and 1 <= offset and offset + 4 <= size,
                "ordinary import final source section differs")
        call_address = start + offset - 1
        instruction = _virtual_instruction(elf, call_address)
        require(instruction[0] == source.get("opcode", 0xe8), "ordinary import final direct-call opcode differs")
        target = call_address + 5 + struct.unpack_from("<i", instruction, 1)[0]
        require(target == provider_address, "ordinary import final call resolves to a foreign provider")
        resolved.append({"section": section, "offset": offset,
                         "call_address": call_address, "target_address": target})
    require(resolved, "ordinary import final ELF has no selected call")
    return {"resolved_calls": resolved, "discarded_calls": discarded}


def _final_symbol(elf: Elf, name: str, binding: str) -> dict[str, Any]:
    symbol = elf.symbol(name, dynamic=False)
    require(symbol["type"] == "FUNC" and symbol["binding"] == binding
            and symbol["visibility"] == "DEFAULT" and symbol["value"] > 0
            and symbol["size"] > 0, "ordinary import final provider metadata differs")
    for relocations in elf.sections:
        if relocations[1] != 4:
            continue
        require(relocations[9] == 24 and relocations[5] % 24 == 0,
                "ordinary import final relocation section differs")
        for offset in range(0, relocations[5], 24):
            _destination, info, _addend = elf.unpack("<QQq", relocations[4] + offset)
            require(elf.symbol_row(relocations[6], info >> 32)["name"] != name,
                    "ordinary import final ELF retains a named relocation")
    return symbol


INT128_CAST_NAMES = ("__fixdfti", "__fixunsdfti", "__floattidf", "__floatuntidf")


def _owned_helper_bytes(elf: Elf, address: int, size: int, *, executable: bool) -> bytes:
    matches = [elf.data[row[2] + address - row[3]:row[2] + address - row[3] + size]
               for row in elf.programs if row[0] == 1 and not row[1] & 2
               and (not executable or row[1] & 1)
               and row[3] <= address and address + size <= row[3] + row[5]]
    require(size > 0 and len(matches) == 1 and len(matches[0]) == size,
            "compiler-helper provider bytes leave one immutable load segment")
    return matches[0]


def _owned_helper_provider_closure(member: Elf, final: Elf, map_lines: Sequence[str],
                                   archive: str, original: Mapping[str, Any],
                                   provider: Mapping[str, Any]) -> dict[str, Any]:
    """Replay complete owned code and its file-local branch/constant dependencies.

    The selected archive has only direct signed-division branches and binary64
    constant references. Only their PC-relative relocation forms are admitted.
    Immutable mergeable constant entries may share equal final storage; their
    complete source entry bytes must still match. Other operands stay unproved.
    """

    symbols = [member.symbol_row(index, number)
               for index, table in enumerate(member.sections) if table[1] == 2
               for number in range(table[5] // 24)]
    code: dict[int, dict[str, Any]] = {}
    constants: dict[tuple[int, int, int], dict[str, Any]] = {}

    def contribution(index: int) -> tuple[int, int]:
        section = _elf_section_name(member, index)
        rows = [line for line in map_lines if line.rstrip().endswith(f"{archive}({ARCHIVE_MEMBER}):({section})")]
        require(len(rows) == 1, "compiler-helper provider contribution is missing or ambiguous")
        fields = rows[0].split()
        require(len(fields) >= 5, "compiler-helper provider contribution fields differ")
        return int(fields[0], 16), int(fields[2], 16)

    def visit(source: Mapping[str, Any], expected: Mapping[str, Any] | None = None) -> None:
        index = source["section"]
        require(0 < index < len(member.sections), "compiler-helper provider source section differs")
        section = member.sections[index]
        name = _elf_section_name(member, index)
        require(source["type"] == "FUNC" and source["binding"] in {"GLOBAL", "LOCAL"}
                and source["visibility"] == "DEFAULT" and source["value"] == 0
                and source["size"] == section[5] and section[5] > 0
                and section[1] == 1 and section[2] & 4 and not section[2] & 1,
                "compiler-helper provider is not one complete owned function section")
        address, size = contribution(index)
        observed = final.symbol(source["name"], dynamic=False) if expected is None else expected
        require(observed["type"] == "FUNC" and observed["binding"] == source["binding"]
                and observed["visibility"] == "DEFAULT" and observed["value"] == address
                and observed["size"] == size == source["size"],
                "compiler-helper final private provider metadata or contribution differs")
        if index in code:
            return
        original_bytes = member.data[section[4]:section[4] + section[5]]
        final_bytes = _owned_helper_bytes(final, address, size, executable=True)
        patched = bytearray(original_bytes)
        record: dict[str, Any] = {"section": name, "address": address, "size": size, "relocations": []}
        code[index] = record
        operands: set[int] = set()
        for relocations in member.sections:
            if relocations[1] not in {4, 9} or relocations[7] != index or not relocations[5]:
                continue
            require(relocations[1] == 4 and relocations[9] == 24 and relocations[5] % 24 == 0,
                    "compiler-helper provider relocation table differs")
            for offset in range(0, relocations[5], 24):
                destination, info, addend = member.unpack("<QQq", relocations[4] + offset)
                symbol = member.symbol_row(relocations[6], info >> 32)
                kind = info & 0xffffffff
                require(kind in {2, 4} and addend == -4 and 1 <= destination
                        and destination + 4 <= size and not operands.intersection(range(destination, destination + 4))
                        and 0 < symbol["section"] < len(member.sections),
                        "compiler-helper provider operand is not an owned PC-relative relocation")
                operands.update(range(destination, destination + 4))
                target_index = symbol["section"]
                target_section = member.sections[target_index]
                target = address + destination + 4 + struct.unpack_from("<i", final_bytes, destination)[0]
                if kind == 4:
                    require(original_bytes[destination - 1] in {0xe8, 0xe9},
                            "compiler-helper provider branch opcode differs")
                    candidates = [row for row in symbols if row["section"] == target_index
                                  and row["type"] == "FUNC" and row["value"] == symbol["value"]]
                    require(len(candidates) == 1 and target == contribution(target_index)[0] + symbol["value"],
                            "compiler-helper provider branch resolves to foreign code")
                    visit(candidates[0])
                else:
                    # Binary80 recovery also uses binary32 infinity constants.
                    # Each relocation must select the complete immutable entry.
                    entry = target_section[9]
                    source_offset = symbol["value"]
                    require(symbol["binding"] == "LOCAL" and symbol["visibility"] == "DEFAULT"
                            and symbol["type"] in {"0", "OBJECT"} and target_section[1] == 1
                            and target_section[2] & 2 and target_section[2] & 16
                            and not target_section[2] & 5 and entry in {4, 8, 16}
                            and source_offset % entry == 0 and source_offset + entry <= target_section[5],
                            "compiler-helper provider constant is not a complete immutable source entry")
                    # LLD pools mergeable entries and omits their original
                    # object contribution rows. The code operand must still
                    # select the complete immutable source entry bytes.
                    expected_bytes = member.data[target_section[4] + source_offset:target_section[4] + source_offset + entry]
                    require(_owned_helper_bytes(final, target, entry, executable=False) == expected_bytes,
                            "compiler-helper provider constant bytes differ from owned source")
                    constants[(target_index, source_offset, target)] = {
                        "section": _elf_section_name(member, target_index), "source_offset": source_offset,
                        "address": target, "size": entry}
                patched[destination:destination + 4] = final_bytes[destination:destination + 4]
                record["relocations"].append({"offset": destination, "kind": kind, "target_address": target})
        require(bytes(patched) == final_bytes, "compiler-helper provider code bytes differ from owned source")

    visit(original, provider)
    return {"code": list(code.values()), "constants": list(constants.values())}


def _compiler_helper_transfers(*, root: Path, archive: Path, workload: Path,
                               executable: Path, map_path: Path, trace_path: Path | None = None,
                               trace_lines: Sequence[str] | None = None, source_mount: str = "/workspace",
                               names: Sequence[str] | None = None) -> dict[str, Any]:
    """Join emitted object relocations to the exact owned archive and final code."""

    root = Path(root).absolute()
    archive, workload, executable, map_path = map(Path, (archive, workload, executable, map_path))
    paths = (archive, workload, executable, map_path, *((Path(trace_path),) if trace_path is not None else ()))
    require(all(path.is_absolute() and path.is_relative_to(root) and path.is_file() and not path.is_symlink()
                for path in paths),
            "compiler-helper retained inputs escape the physical checkout")
    recorded_archive = source_mount + "/" + archive.relative_to(root).as_posix()
    recorded_workload = source_mount + "/" + workload.relative_to(root).as_posix()
    map_lines = map_path.read_text(encoding="utf-8").splitlines()
    require((trace_path is None) != (trace_lines is None), "compiler-helper trace authority is ambiguous")
    trace_lines = Path(trace_path).read_text(encoding="utf-8").splitlines() if trace_path is not None else trace_lines
    require(type(trace_lines) is list and all(type(line) is str for line in trace_lines),
            "compiler-helper trace rows differ")
    require(trace_lines.count(f"{recorded_archive}({ARCHIVE_MEMBER})") == 1,
            "compiler-helper trace does not extract the exact owned member")
    require(trace_lines.count(recorded_workload) == 1,
            "compiler-helper trace does not name the retained compiler object")
    require(re.search(r"libgcc|compiler-rt", "\n".join(trace_lines)) is None,
            "compiler-helper trace admits an ambient compiler runtime")
    source = Elf(workload)
    final = Elf(executable)
    require(source.elf_type == 1 and final.elf_type in {2, 3}, "compiler-helper ELF kinds differ")
    archive_bytes = _archive_object_bytes(archive, ARCHIVE_MEMBER)
    scratch = root / ".work/x86_64/tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch) as temporary:
        member_path = Path(temporary) / ARCHIVE_MEMBER
        member_path.write_bytes(archive_bytes)
        member = Elf(member_path)
        result = {}
        selected = helper_names(load_contract(root)) if names is None else tuple(names)
        require(selected and len(selected) == len(set(selected))
                and set(selected) <= set(helper_names(load_contract(root))),
                "compiler-helper selected provider roster differs")
        for name in selected:
            imports = [source.symbol_row(index, number)
                       for index, table in enumerate(source.sections) if table[1] == 2
                       for number in range(table[5] // 24)
                       if source.symbol_row(index, number)["name"] == name]
            require(len(imports) == 1 and imports[0]["section"] == 0 and imports[0]["binding"] == "GLOBAL",
                    "compiler-helper compiler object import differs")
            provider = _final_symbol(final, name, "GLOBAL")
            original = member.symbol(name, dynamic=False)
            require(original["type"] == "FUNC" and original["binding"] == "GLOBAL"
                    and original["visibility"] == "DEFAULT" and original["size"] == provider["size"]
                    and original["section"] > 0,
                    "compiler-helper owned archive provider metadata differs")
            section = _elf_section_name(member, original["section"])
            require(section == ".text." + name, "compiler-helper archive source section differs")
            provider_rows = [line for line in map_lines if line.rstrip().endswith(":(" + section + ")")]
            require(len(provider_rows) == 1
                    and provider_rows[0].rstrip().endswith(f"{recorded_archive}({ARCHIVE_MEMBER}):({section})")
                    and int(provider_rows[0].split()[0], 16) + original["value"] == provider["value"]
                    and int(provider_rows[0].split()[2], 16) == member.sections[original["section"]][5],
                    "compiler-helper final provider does not originate in the owned archive")
            closure = _owned_helper_provider_closure(member, final, map_lines, recorded_archive, original, provider)
            calls = _direct_source_calls(workload.read_bytes(), name, root, allow_tail_calls=True)
            addresses = {}
            for source_section in {row["section"] for row in calls}:
                rows = [line for line in map_lines if line.rstrip().endswith(f"{recorded_workload}:({source_section})")]
                require(len(rows) == 1, "compiler-helper compiler contribution is missing or ambiguous")
                fields = rows[0].split()
                addresses[source_section] = (int(fields[0], 16), int(fields[2], 16))
            result[name] = {"provider_address": provider["value"], "source_section": section,
                            "provider_closure": closure,
                            **_final_direct_calls(final, calls, addresses, provider["value"])}
    return {"archive_sha256": digest(archive), "workload_sha256": digest(workload),
            "executable_sha256": digest(executable), "transfers": result}


def _integer128_cast_transfers(*, root: Path, archive: Path, workload: Path,
                               executable: Path, map_path: Path, trace_path: Path | None = None,
                               trace_lines: Sequence[str] | None = None,
                               source_mount: str = "/workspace") -> dict[str, Any]:
    """Keep the finite cast projection on the complete owned-provider reader."""

    observations = _compiler_helper_transfers(root=root, archive=archive, workload=workload,
        executable=executable, map_path=map_path, trace_path=trace_path,
        trace_lines=trace_lines, source_mount=source_mount, names=INT128_CAST_NAMES)
    for row in observations["transfers"].values():
        row.pop("provider_closure")
    return observations


def _retained_compiler_helper_link(*, root: Path, product: Path, workload: Path,
                                  executable: Path, receipt: Path, linkage: str,
                                  linker: Mapping[str, str], names: Sequence[str] | None = None) -> dict[str, Any]:
    """Authenticate an installed link before admitting complete helper origins."""

    import owned_posix_product_evidence as products
    identity = products.validate_retained_link(root, "/workspace", product, workload,
                                              executable, receipt, linkage, dict(linker))
    record = _read_json(receipt, "compiler-helper link receipt")
    if linkage in {"static", "static-pie"}:
        map_path = receipt.parent / record["map"]["path"]
        trace_arguments = {"trace_path": receipt.parent / record["trace"]["path"]}
    else:
        import owned_dynamic_elf as dynamic_elf
        sidecar, map_path = dynamic_elf.sidecar_paths(executable)
        dynamic_elf.validate_record(_read_json(sidecar, "compiler-helper ELF sidecar"), executable,
                                   output_format=products.DYNAMIC_PRODUCT_FORMAT,
                                   fail=lambda message: require(False, message),
                                   recorded_path=lambda path: "/workspace/" + path.relative_to(root).as_posix())
        trace_arguments = {"trace_lines": record["link_trace"]}
    observations = _compiler_helper_transfers(
        root=root, archive=product / "usr/lib/libcrabc-builtins.a", workload=workload,
        executable=executable, map_path=map_path, names=names, **trace_arguments)
    return {"link": identity, **observations}


def retained_compiler_helper_link(*, root: Path, product: Path, workload: Path,
                                  executable: Path, receipt: Path, linkage: str,
                                  linker: Mapping[str, str]) -> dict[str, Any]:
    """Admit every selected helper, its complete owned body, and all consumer sites."""

    return _retained_compiler_helper_link(root=root, product=product, workload=workload,
        executable=executable, receipt=receipt, linkage=linkage, linker=linker)


def retained_integer128_cast_link(*, root: Path, product: Path, workload: Path,
                                  executable: Path, receipt: Path, linkage: str,
                                  linker: Mapping[str, str]) -> dict[str, Any]:
    """Preserve the cast caller projection through the complete helper join."""

    observations = _retained_compiler_helper_link(root=root, product=product, workload=workload,
        executable=executable, receipt=receipt, linkage=linkage, linker=linker, names=INT128_CAST_NAMES)
    for row in observations["transfers"].values():
        row.pop("provider_closure")
    return observations


def _popcount_import_from_facts(facts_report: Mapping[str, Any], placements: Mapping[str, Any]) -> dict[str, Any]:
    """Bind the one static ordinary import to the selected archive member.

    This reads complete facts rather than an equal value, an archive byte hash,
    or the same-name shared-libc definition.  The ordinary-link reader supplies
    the later map/trace and final-link evidence.
    """

    facts = facts_report.get("facts")
    require(type(facts) is dict and type(facts.get("candidate-static")) is list,
            "complete facts candidate-static placement differs")
    rows = []
    for member in facts["candidate-static"]:
        if not isinstance(member, dict):
            continue
        for table in member.get("symbol_tables", []):
            if not isinstance(table, dict):
                continue
            for row in table.get("rows", []):
                if isinstance(row, dict) and row.get("name") == "__popcountdi2":
                    rows.append({"member": member, "table": table, "row": row})
    require(len(rows) == 1, "complete facts __popcountdi2 import is not unique")
    entry = rows[0]
    row = entry["row"]
    require(entry["table"].get("name") == ".symtab" and row.get("section_index") == "UND"
            and same({key: row.get(key) for key in HELPER_METADATA}, {
                **HELPER_METADATA, "type": "NOTYPE"
            }), "complete facts __popcountdi2 import metadata differs")
    definition = placements["static-builtins"].get("__popcountdi2")
    require(same(definition, {"member": ARCHIVE_MEMBER, "section": ".text.__popcountdi2",
                              "metadata": HELPER_METADATA}),
            "selected static-builtins __popcountdi2 definition differs")
    return {"identity": "__popcountdi2", "consumer_artifact": "candidate-static",
            "consumer_member": entry["member"].get("member"), "consumer_member_index": entry["member"].get("member_index"),
            "consumer_member_occurrence": entry["member"].get("member_occurrence"),
            "consumer_symtab_row": row.get("row_index"), "provider_placement": "static-builtins",
            "provider_member": ARCHIVE_MEMBER, "provider_section": ".text.__popcountdi2"}


def _ordinary_popcount_maps(root: Path, ordinary_report: Path, expected_inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Replay the public-data reader, then retain only the two exact map joins."""

    _elf_facts, ordinary = _load_companion_modules()
    report_path = Path(ordinary_report).absolute()
    replay = ordinary.validate_report(root, report_path)
    require(type(replay) is dict and set(replay) == {"report", "links"},
            "ordinary-link replay boundary differs")
    replay_identity = replay["report"]
    current_before = ordinary.work_file_identity(root, report_path, "ordinary-link report")
    require(same(replay_identity, current_before), "ordinary-link report changed after replay")
    raw = _read_json(report_path, "ordinary-link report")
    current_after = ordinary.work_file_identity(root, report_path, "ordinary-link report")
    require(same(replay_identity, current_after) and same(current_before, current_after),
            "ordinary-link report changed while attaching compiler-helper evidence")
    require(type(raw) is dict and same(raw.get("source_before"), expected_inputs)
            and same(raw.get("source_after"), expected_inputs),
            "ordinary-link report uses a different supplied product cohort")
    work = report_path.parent
    links = raw.get("links") if type(raw) is dict else None
    require(type(links) is dict and set(links) == {"static", "static-pie", "dynamic-pie", "dynamic-non-pie"},
            "ordinary-link link roster differs")
    result: dict[str, Any] = {}
    expected = f"libcrabc-builtins.a({ARCHIVE_MEMBER}):(.text.__popcountdi2)"
    for mode in ("static", "static-pie"):
        record = links[mode]
        require(type(record) is dict and type(record.get("receipt")) is dict,
                f"ordinary-link {mode} receipt differs")
        # The ordinary report seals receipt paths relative to the checkout.
        # Each driver receipt then names its adjacent map and trace relative
        # to this report directory; these are distinct path contracts.
        receipt_path = ordinary.resolve_work_identity(root, record["receipt"],
                                                      f"ordinary-link {mode} receipt")
        receipt_identity_before = _work_identity(work, receipt_path, f"ordinary-link {mode} receipt")
        receipt = _read_json(_physical_file(receipt_path, f"ordinary-link {mode} receipt"),
                             f"ordinary-link {mode} receipt")
        require(same(receipt_identity_before, _work_identity(work, receipt_path, f"ordinary-link {mode} receipt")),
                f"ordinary-link {mode} receipt changed while reading")
        require(type(receipt) is dict and type(receipt.get("map")) is dict and type(receipt.get("trace")) is dict,
                f"ordinary-link {mode} map/trace differs")
        map_path = work / receipt["map"].get("path", "")
        trace_path = work / receipt["trace"].get("path", "")
        map_identity = _work_identity(work, map_path, f"ordinary-link {mode} map")
        trace_identity = _work_identity(work, trace_path, f"ordinary-link {mode} trace")
        require(type(receipt["map"].get("sha256")) is str and receipt["map"]["sha256"] == map_identity["sha256"]
                and type(receipt["trace"].get("sha256")) is str and receipt["trace"]["sha256"] == trace_identity["sha256"],
                f"ordinary-link {mode} map/trace identity differs")
        map_text = map_path.read_text(encoding="utf-8", errors="replace")
        trace_text = trace_path.read_text(encoding="utf-8", errors="replace")
        require(same(map_identity, _work_identity(work, map_path, f"ordinary-link {mode} map"))
                and same(trace_identity, _work_identity(work, trace_path, f"ordinary-link {mode} trace")),
                f"ordinary-link {mode} map/trace changed while reading")
        provider_rows = [line for line in map_text.splitlines()
                         if line.rstrip().endswith(":(.text.__popcountdi2)")]
        require(len(provider_rows) == 1 and expected in provider_rows[0],
                f"ordinary-link {mode} __popcountdi2 provider map is ambiguous")
        require(f"libcrabc-builtins.a({ARCHIVE_MEMBER})" in trace_text,
                f"ordinary-link {mode} trace does not extract the builtins member")
        result[mode] = {"map": map_identity, "trace": trace_identity,
                        "member": ARCHIVE_MEMBER, "section": ".text.__popcountdi2"}
    return {"ordinary_report": replay_identity, "static_modes": result}


def validate_supplied_product_evidence(*, root: Path, base_inventory: Path, elf_report: Path,
                                       static_preparation: Path, static_product: Path, dynamic_product: Path,
                                       ordinary_link_report: Path | None,
                                       aggregate_report: Path | None) -> dict[str, Any]:
    """Replay fresh supplied products without creating a second product builder.

    The complete-ELF reader authenticates the inventory, preparation, and both
    product identities.  This component then takes only its two archive
    placements and, when supplied, the one static ordinary import.  A caller
    cannot use an old receipt after this producer contract changes because the
    product readers and this source binding are both current-checkout checks.
    """

    root = Path(root).absolute()
    contract = load_contract(root)
    current_source = source_binding(root, contract)
    elf_facts, ordinary = _load_companion_modules()
    try:
        ordinary_inputs = ordinary.admit_inputs(root, Path(static_preparation), Path(static_product), Path(dynamic_product))
        facts = elf_facts.validate_report(Path(elf_report), base_inventory=Path(base_inventory),
                                          static_product=Path(static_product), dynamic_product=Path(dynamic_product),
                                          static_preparation=Path(static_preparation))
        placements = archive_placements_from_elf_facts(facts, contract)
        shared_projection = shared_libc_placement_from_elf_facts(facts, contract)
        installed_archives = _installed_archive_identities(facts)
    except CompilerHelperEvidenceError:
        raise
    except (elf_facts.inventory.InventoryError, OSError, ValueError) as error:
        raise CompilerHelperEvidenceError("supplied complete ELF/product evidence is not current and valid") from error
    aggregate_join: dict[str, Any]
    if aggregate_report is None:
        aggregate_join = {"status": "not-supplied-partial",
                          "reason": "No source-matched aggregate C ABI receipt was supplied for both installed archives."}
    else:
        try:
            aggregate_join = {"status": "joined", **_aggregate_archive_join(
                root, Path(aggregate_report), supplied_source=ordinary_inputs["source"],
                installed_archives=installed_archives)}
        except CompilerHelperEvidenceError:
            raise
        except (OSError, ValueError) as error:
            raise CompilerHelperEvidenceError("supplied compiler-helper aggregate evidence is not current and valid") from error
    result = {"source": current_source, "archive_placements": placements,
              "installed_archive_identities": installed_archives, "aggregate_c_abi": aggregate_join,
              "shared_libc_projection": shared_projection,
              "shared_placement_selected": False, "family_completion": False,
              "public_support": False}
    if ordinary_link_report is not None:
        try:
            import_join = _popcount_import_from_facts(facts, placements)
            ordinary_links = _ordinary_popcount_maps(root, Path(ordinary_link_report), ordinary_inputs)
            importer = import_join["consumer_member"]
            object_bytes = _archive_object_bytes(Path(static_product) / "usr/lib/libc.a", importer)
            object_sha256 = hashlib.sha256(object_bytes).hexdigest()
            provenance = _read_json(Path(dynamic_product) / "share/crabc/libc-shared.provenance.json",
                                    "shared libc provenance")
            require(type(provenance.get("selected_members")) is dict
                    and provenance["selected_members"].get(importer) == object_sha256,
                    "ordinary import C object differs from the shared libc selected member")
            source_calls = _direct_source_calls(object_bytes, import_join["identity"], root)
            work = Path(ordinary_link_report).absolute().parent
            final_links = {}
            for mode, elf_type in (("static", 2), ("static-pie", 3)):
                link = ordinary_links["static_modes"][mode]
                map_path = _resolve_work_identity(work, link["map"], mode + " final map")
                map_lines = map_path.read_text(encoding="utf-8").splitlines()
                elf = Elf(work / mode)
                require(elf.elf_type == elf_type, "ordinary import final executable kind differs")
                provider = _final_symbol(elf, import_join["identity"], "GLOBAL")
                provider_rows = [line for line in map_lines
                                 if line.rstrip().endswith(f"libcrabc-builtins.a({ARCHIVE_MEMBER}):(.text.__popcountdi2)")]
                require(len(provider_rows) == 1 and int(provider_rows[0].split()[0], 16) == provider["value"],
                        "ordinary import final provider map or symbol differs")
                source_addresses = {}
                for section in {row["section"] for row in source_calls}:
                    rows = [line for line in map_lines
                            if line.rstrip().endswith(f"libc.a({importer}):({section})")]
                    require(len(rows) <= 1, "ordinary import final C source map is ambiguous")
                    if rows:
                        fields = rows[0].split()
                        require(len(fields) >= 5, "ordinary import final C source map differs")
                        source_addresses[section] = (int(fields[0], 16), int(fields[2], 16))
                final_links[mode] = {"provider_address": provider["value"],
                                     **_final_direct_calls(elf, source_calls, source_addresses, provider["value"])}
            shared = Elf(Path(dynamic_product) / "usr/lib/libc.so")
            require(shared.elf_type == 3 and shared.symbol(import_join["identity"],
                                                            dynamic=True, required=False) is None,
                    "ordinary import shared provider is exported or is not ELF DYN")
            shared_provider = _final_symbol(shared, import_join["identity"], "LOCAL")
            shared_sources = {}
            for section in {row["section"] for row in source_calls}:
                caller = shared.symbol(section.removeprefix(".text."), dynamic=False, required=False)
                if caller is not None:
                    require(caller["type"] == "FUNC" and caller["binding"] == "LOCAL"
                            and caller["visibility"] == "DEFAULT", "ordinary import shared C caller differs")
                    shared_sources[section] = (caller["value"], caller["size"])
            final_links["shared-libc"] = {"provider_address": shared_provider["value"],
                                           **_final_direct_calls(shared, source_calls, shared_sources,
                                                                 shared_provider["value"])}
        except CompilerHelperEvidenceError:
            raise
        except (ordinary.PublicDataEvidenceError, EvidenceError, OSError, ValueError) as error:
            raise CompilerHelperEvidenceError("supplied ordinary __popcountdi2 evidence is not current and valid") from error
        result["ordinary_popcount_import"] = {
            **import_join, "ordinary_links": ordinary_links,
            "source_object_sha256": object_sha256, "source_calls": source_calls,
            "final_links": final_links,
        }
    else:
        result["ordinary_popcount_import"] = None
    return result


AGGREGATE_COMMANDS = (
    ("builder", 0),
    ("candidate-compile", 0),
    ("start-compile", 0),
    ("candidate-imports", 0),
    ("archive-free-link", "nonzero"),
    ("candidate-link", 0),
    ("candidate-definitions", 0),
    ("candidate-undefined", 0),
    ("candidate-header", 0),
    ("candidate-program-headers", 0),
    ("candidate-dynamic", 0),
    ("candidate-disassembly", 0),
    ("reference-compile", 0),
    ("reference-link", 0),
    ("reference-execute", 0),
    ("candidate-execute", 0),
)
AGGREGATE_ARTIFACTS = (
    "libcrabc-builtins.a",
    "libcrabc-builtins.a.provenance.json",
    "aggregate.o",
    "aggregate-start.o",
    "candidate",
    "pinned-musl-reference.o",
    "pinned-musl-reference",
)
COMPLEX_EDGE_SCHEMA = "crabc.x86_64-compiler-helper-complex-edge/v1"
COMPLEX_EDGE_SOURCE = Path("compat/x86_64/complex_mul_support.c")
COMPLEX_EDGE_CASES = 13 ** 4
COMPLEX_EDGE_TRANSCRIPT = f"complex-edge-ok {COMPLEX_EDGE_CASES}\n".encode("ascii")
# The source oracle and owned archive are separate linked objects. Compare NaN
# classification, but keep exact bits for every other result, including zero.
COMPLEX_EDGE_PROBE = r'''#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef double _Complex complex_double;
extern complex_double __muldc3(double, double, double, double);
extern complex_double crabc_reference_muldc3(double, double, double, double);
static uint64_t bits(double value) {
    uint64_t result;
    memcpy(&result, &value, sizeof result);
    return result;
}
static int same(double left, double right) {
    return (isnan(left) && isnan(right)) || bits(left) == bits(right);
}
int main(void) {
    volatile double values[] = {
        0.0, -0.0, 1.0, -1.0, 2.0, -2.0,
        0x1p1023, -0x1p1023, 0x1p-1074, -0x1p-1074,
        INFINITY, -INFINITY, NAN
    };
    unsigned cases = 0;
    for (unsigned a = 0; a < 13; ++a)
    for (unsigned b = 0; b < 13; ++b)
    for (unsigned c = 0; c < 13; ++c)
    for (unsigned d = 0; d < 13; ++d) {
        complex_double owned = __muldc3(values[a], values[b], values[c], values[d]);
        complex_double oracle = crabc_reference_muldc3(values[a], values[b], values[c], values[d]);
        if (!same(__real__ owned, __real__ oracle) ||
            !same(__imag__ owned, __imag__ oracle)) {
            fprintf(stderr, "complex mismatch %u %u %u %u: %llx %llx / %llx %llx\n",
                    a, b, c, d,
                    (unsigned long long)bits(__real__ owned),
                    (unsigned long long)bits(__imag__ owned),
                    (unsigned long long)bits(__real__ oracle),
                    (unsigned long long)bits(__imag__ oracle));
            return 1;
        }
        ++cases;
    }
    printf("complex-edge-ok %u\n", cases);
    return 0;
}
'''
COMPLEX_EDGE_ARTIFACTS = (
    "libcrabc-builtins.a", "libcrabc-builtins.a.provenance.json",
    "libm.h", "complex-edge-probe.c", "complex-edge-oracle.o",
    "complex-edge-probe.o", "complex-edge-candidate", "complex-edge-commands.json",
)
EXPECTED_TRANSCRIPT = b"compiler-helper-aggregate-ok\n"
IMAGE_PATTERN = re.compile(r"crabc-core-evidence@sha256:[0-9a-f]{64}\Z")
SOURCE_MOUNT = "/workspace"
ORACLE_CC = "/usr/local/bin/crabc-x86_64-musl-gcc"
ORACLE_UNSETS = ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "GCC_EXEC_PREFIX", "COMPILER_PATH")


def _read_json(path: Path, description: str) -> Any:
    """Read JSON while rejecting duplicate keys and non-finite constants."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, f"{description} has a duplicate key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(
                              CompilerHelperEvidenceError(f"{description} has an invalid JSON constant: {value}")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CompilerHelperEvidenceError(f"{description} is unreadable") from error


def _physical_directory(path: Path, description: str) -> Path:
    path = Path(path).absolute()
    require(path.is_dir() and not path.is_symlink() and path.resolve() == path,
            f"{description} is not a physical directory")
    return path


def _physical_file(path: Path, description: str) -> Path:
    path = Path(path).absolute()
    require(path.is_file() and not path.is_symlink() and path.resolve() == path,
            f"{description} is not a physical regular file")
    return path


def checkout_work_directory(root: Path, path: Path, *, product: Path | None = None) -> Path:
    """Resolve a not-yet-created runner directory beneath physical x86 work.

    A runner accepts a caller path before it creates it, so a lexical prefix is
    insufficient: ``..`` and an existing intermediate symlink can otherwise
    carry its product and raw evidence outside the checkout.  Resolve the
    prospective path first, then let the runner enforce freshness before it
    creates anything.
    """

    root = _physical_directory(root, "compiler-helper checkout")
    allowed = _physical_directory(root / ".work/x86_64", "compiler-helper checkout .work/x86_64")
    resolved = Path(path).absolute().resolve(strict=False)
    require(resolved != allowed and resolved.is_relative_to(allowed),
            "compiler-helper work directory must be a physical checkout .work/x86_64 descendant")
    if product is not None:
        supplied = _physical_directory(product, "compiler-helper supplied dynamic product")
        require(supplied != allowed and supplied.is_relative_to(allowed),
                "compiler-helper supplied dynamic product escapes checkout .work/x86_64")
        require(not resolved.is_relative_to(supplied),
                "compiler-helper work directory overlaps the supplied dynamic product")
    return resolved


def validate_materialized_dynamic_product(root: Path, product: Path) -> str:
    """Use the owned product reader before and after private execution copies."""

    root = _physical_directory(root, "compiler-helper checkout")
    product = _physical_directory(product, "compiler-helper installed dynamic product")
    require(product.is_relative_to(_physical_directory(root / ".work/x86_64", "compiler-helper checkout .work/x86_64")),
            "compiler-helper installed dynamic product escapes checkout .work/x86_64")
    module_dir = Path(__file__).resolve().parent
    if str(module_dir) not in sys.path:
        sys.path.insert(0, str(module_dir))
    import owned_dynamic_qualification as qualification
    try:
        return qualification.product_identity(product)
    except (qualification.QualificationError, OSError, ValueError) as error:
        raise CompilerHelperEvidenceError("compiler-helper installed dynamic product is not admitted") from error


def _work_identity(work: Path, path: Path, description: str) -> dict[str, Any]:
    work = _physical_directory(work, "compiler-helper work")
    path = _physical_file(path, description)
    require(path.is_relative_to(work), f"{description} escapes compiler-helper work")
    relative = path.relative_to(work)
    return {"path": relative.as_posix(), "sha256": digest(path), "size": path.stat().st_size,
            "mode": path.stat().st_mode & 0o777}


def _resolve_work_identity(work: Path, value: object, description: str) -> Path:
    require(type(value) is dict and set(value) == {"path", "sha256", "size", "mode"},
            f"{description} identity fields differ")
    relative = value["path"]
    require(type(relative) is str and relative and not Path(relative).is_absolute()
            and ".." not in Path(relative).parts, f"{description} path differs")
    path = _physical_file(work / relative, description)
    require(same(value, _work_identity(work, path, description)), f"{description} bytes differ")
    return path


def _external_file_identity(path: Path, description: str) -> dict[str, Any]:
    path = _physical_file(path, description)
    return {"path": path.as_posix(), "sha256": digest(path), "size": path.stat().st_size,
            "mode": path.stat().st_mode & 0o777}


def capture_oracle_compiler(output: Path, *, work: Path, compiler: Path) -> dict[str, Any]:
    """Retain the compiler wrapper used by the native aggregate commands.

    The commands retain the fixed wrapper path.  This record additionally
    keeps the exact wrapper bytes inside the checkout-local receipt, and the
    aggregate writer compares the live wrapper again after all commands run.
    """

    work = _physical_directory(work, "compiler-helper work")
    output = Path(output).absolute()
    require(output.parent == work and output.name == "oracle-compiler.json" and not output.exists()
            and not output.is_symlink(), "compiler-helper oracle compiler record output differs")
    compiler = _physical_file(compiler, "compiler-helper pinned musl compiler")
    require(compiler == Path(ORACLE_CC), "compiler-helper pinned musl compiler path differs")
    retained = work / "inputs" / "pinned-musl-compiler"
    require(not retained.exists() and not retained.is_symlink(), "compiler-helper retained oracle compiler already exists")
    # The collector runs in the pinned container; host replay needs traversal
    # permission for this immutable retained tool file after the container exits.
    retained.parent.mkdir(mode=0o755)
    shutil.copyfile(compiler, retained)
    retained.chmod(compiler.stat().st_mode & 0o777)
    record = {"schema": "crabc.x86_64-compiler-helper-oracle-compiler/v1",
              "original": _external_file_identity(compiler, "compiler-helper pinned musl compiler"),
              "retained": _work_identity(work, retained, "compiler-helper retained musl compiler")}
    output.write_text(canonical_json(record), encoding="utf-8")
    return record


def _oracle_compiler_record(work: Path, path: Path, *, verify_current: bool) -> dict[str, Any]:
    path = _physical_file(path, "compiler-helper oracle compiler record")
    require(path.parent == work and path.name == "oracle-compiler.json",
            "compiler-helper oracle compiler record path differs")
    record = _read_json(path, "compiler-helper oracle compiler record")
    require(type(record) is dict and set(record) == {"schema", "original", "retained"}
            and record["schema"] == "crabc.x86_64-compiler-helper-oracle-compiler/v1",
            "compiler-helper oracle compiler record fields differ")
    original, retained = record["original"], record["retained"]
    require(type(original) is dict and set(original) == {"path", "sha256", "size", "mode"}
            and original.get("path") == ORACLE_CC and type(original.get("sha256")) is str
            and re.fullmatch(r"[0-9a-f]{64}", original["sha256"]) is not None
            and type(original.get("size")) is int and original["size"] > 0
            and type(original.get("mode")) is int and 0 <= original["mode"] <= 0o777,
            "compiler-helper oracle compiler original identity differs")
    retained_path = _resolve_work_identity(work, retained, "compiler-helper retained musl compiler")
    require(same(original["sha256"], digest(retained_path)) and original["size"] == retained_path.stat().st_size
            and original["mode"] == (retained_path.stat().st_mode & 0o777),
            "compiler-helper retained musl compiler differs from original")
    if verify_current:
        require(same(original, _external_file_identity(Path(ORACLE_CC), "compiler-helper pinned musl compiler")),
                "compiler-helper pinned musl compiler changed during aggregate execution")
    return record


def _checkout_identity(root: Path) -> dict[str, Any]:
    """Require a clean committed checkout for a native aggregate receipt."""

    root = Path(root).absolute()
    try:
        revision = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, text=True,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()
        status = subprocess.run(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
                                check=True, text=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise CompilerHelperEvidenceError("compiler-helper checkout identity is unavailable") from error
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None and status == "",
            "compiler-helper aggregate requires a clean committed checkout")
    return {"revision": revision, "clean": True}


def _product_source_identity(root: Path) -> dict[str, Any]:
    """Use the prepared-product source digest shape for an aggregate join."""

    module_dir = Path(__file__).resolve().parent
    if str(module_dir) not in sys.path:
        sys.path.insert(0, str(module_dir))
    import owned_posix_static_products as static_products
    try:
        value = static_products.source_identity(Path(root).absolute())
    except (static_products.PreparationError, OSError, subprocess.CalledProcessError) as error:
        raise CompilerHelperEvidenceError("compiler-helper aggregate product source identity is unavailable") from error
    require(type(value) is dict and set(value) == {"revision", "content_sha256"}
            and type(value["revision"]) is str and re.fullmatch(r"[0-9a-f]{40}", value["revision"]) is not None
            and type(value["content_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", value["content_sha256"]) is not None,
            "compiler-helper aggregate product source identity differs")
    return value


def capture_source(output: Path, *, root: Path = ROOT) -> dict[str, Any]:
    """Seal current producer and harness sources before a native runner starts."""

    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), "compiler-helper source seal output already exists")
    require(output.parent.is_dir() and not output.parent.is_symlink(), "compiler-helper source seal parent is unsafe")
    checkout = _checkout_identity(root)
    product_source = _product_source_identity(root)
    require(product_source["revision"] == checkout["revision"],
            "compiler-helper aggregate product source revision differs")
    record = {"schema": SOURCE_SEAL_SCHEMA, "source": source_binding(root), "checkout": checkout,
              "product_source": product_source}
    output.write_text(canonical_json(record), encoding="utf-8")
    return record


def _source_seal(path: Path, *, root: Path) -> dict[str, Any]:
    path = _physical_file(path, "compiler-helper source seal")
    record = _read_json(path, "compiler-helper source seal")
    require(type(record) is dict and set(record) == {"schema", "source", "checkout", "product_source"}
            and record["schema"] == SOURCE_SEAL_SCHEMA, "compiler-helper source seal fields differ")
    require(same(record["source"], source_binding(root)) and same(record["checkout"], _checkout_identity(root))
            and same(record["product_source"], _product_source_identity(root)),
            "compiler-helper source changed")
    return record


def append_command_event(events_path: Path, *, work: Path, label: str, status: int,
                         stdout: Path, stderr: Path, argv: Sequence[str], inputs: Sequence[Path]) -> None:
    """Append one actual native command result with its raw streams.

    The runner calls this immediately after each command.  A command cannot be
    retroactively described because its argv, exit status, and two output files
    are all sealed before the aggregate report is written.
    """

    work = _physical_directory(work, "compiler-helper work")
    events_path = Path(events_path).absolute()
    require(events_path.parent == work and events_path.name == "commands.json"
            and not events_path.is_symlink(), "compiler-helper command event path differs")
    require(type(label) is str and label in {item[0] for item in AGGREGATE_COMMANDS},
            "compiler-helper command label differs")
    require(type(status) is int, "compiler-helper command status is not an integer")
    require(type(argv) in {list, tuple} and bool(argv) and all(type(item) is str and item for item in argv),
            "compiler-helper command argv differs")
    event = {"label": label, "argv": list(argv), "status": status,
             "inputs": [_work_identity(work, path, f"{label} input") for path in inputs],
             "stdout": _work_identity(work, stdout, f"{label} stdout"),
             "stderr": _work_identity(work, stderr, f"{label} stderr")}
    if events_path.exists():
        records = _read_json(events_path, "compiler-helper command events")
        require(type(records) is list, "compiler-helper command events differ")
    else:
        records = []
    require(all(type(row) is dict and row.get("label") != label for row in records),
            "compiler-helper command event is duplicated")
    records.append(event)
    events_path.write_text(canonical_json(records), encoding="utf-8")


def _mounted(root: Path, path: Path, source_mount: str) -> str:
    root, path = Path(root).absolute(), Path(path).absolute()
    require(source_mount == SOURCE_MOUNT and path.is_relative_to(root), "compiler-helper source mount differs")
    return (Path(source_mount) / path.relative_to(root)).as_posix()


def _oracle_prefix() -> list[str]:
    result = ["env"]
    for name in ORACLE_UNSETS:
        result.extend(["-u", name])
    result.append(ORACLE_CC)
    return result


def _expected_command_argv(label: str, *, root: Path, work: Path, source_mount: str) -> list[str]:
    mounted = lambda path: _mounted(root, work / path, source_mount)
    source = lambda path: _mounted(root, root / path, source_mount)
    oracle = _oracle_prefix()
    exact = {
        "builder": ["python3", source(BUILDER), "--output", mounted("libcrabc-builtins.a"), "--provenance",
                    mounted("libcrabc-builtins.a.provenance.json"), "--verify-reproducible"],
        "candidate-compile": [*oracle, "-std=c11", "-O2", "-fno-builtin", "-Wno-builtin-declaration-mismatch",
            "-fno-stack-protector", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables", "-ffreestanding",
            "-fno-pic", "-fno-pie", "-DCRABC_BUILTINS_FREESTANDING", "-c", source(AGGREGATE_PROBE), "-o", mounted("aggregate.o")],
        "start-compile": [*oracle, "-c", source(AGGREGATE_START), "-o", mounted("aggregate-start.o")],
        "candidate-imports": ["nm", "--undefined-only", mounted("aggregate.o")],
        "archive-free-link": [*oracle, "-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none",
            "-Wl,--no-undefined", "-Wl,-e,_start", mounted("aggregate-start.o"), mounted("aggregate.o"),
            "-o", mounted("without-archive")],
        "candidate-link": [*oracle, "-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none",
            "-Wl,--no-undefined", "-Wl,-e,_start", "-Wl,-t", mounted("aggregate-start.o"), mounted("aggregate.o"),
            mounted("libcrabc-builtins.a"), "-o", mounted("candidate")],
        "candidate-definitions": ["nm", "--defined-only", mounted("candidate")],
        "candidate-undefined": ["nm", "--undefined-only", mounted("candidate")],
        "candidate-header": ["readelf", "-hW", mounted("candidate")],
        "candidate-program-headers": ["readelf", "-lW", mounted("candidate")],
        "candidate-dynamic": ["readelf", "-dW", mounted("candidate")],
        "candidate-disassembly": ["objdump", "--disassemble", mounted("candidate")],
        "reference-compile": [*oracle, "-std=c11", "-O2", "-fno-stack-protector", "-fno-pie",
            "-DCRABC_HELPER_REFERENCE", "-c", source(AGGREGATE_PROBE), "-o", mounted("pinned-musl-reference.o")],
        "reference-link": [*oracle, "-no-pie", mounted("pinned-musl-reference.o"), "-o", mounted("pinned-musl-reference")],
        "reference-execute": [mounted("pinned-musl-reference")],
        "candidate-execute": [mounted("candidate")],
    }
    return exact[label]


def _expected_command_inputs(label: str, work: Path) -> list[dict[str, Any]]:
    inputs = {
        "builder": (), "candidate-compile": (), "start-compile": (),
        "candidate-imports": ("aggregate.o",),
        "archive-free-link": ("aggregate-start.o", "aggregate.o"),
        "candidate-link": ("aggregate-start.o", "aggregate.o", "libcrabc-builtins.a"),
        "candidate-definitions": ("candidate",), "candidate-undefined": ("candidate",),
        "candidate-header": ("candidate",), "candidate-program-headers": ("candidate",),
        "candidate-dynamic": ("candidate",), "candidate-disassembly": ("candidate",),
        "reference-compile": (), "reference-link": ("pinned-musl-reference.o",),
        "reference-execute": ("pinned-musl-reference",), "candidate-execute": ("candidate",),
    }[label]
    return [_work_identity(work, work / path, f"{label} input") for path in inputs]


def _command_events(work: Path, events_path: Path, *, root: Path, source_mount: str) -> list[dict[str, Any]]:
    work = _physical_directory(work, "compiler-helper work")
    events_path = _physical_file(events_path, "compiler-helper command events")
    require(events_path.parent == work and events_path.name == "commands.json",
            "compiler-helper command event path differs")
    records = _read_json(events_path, "compiler-helper command events")
    require(type(records) is list and len(records) == len(AGGREGATE_COMMANDS),
            "compiler-helper command roster differs")
    result: list[dict[str, Any]] = []
    for record, (label, expected_status) in zip(records, AGGREGATE_COMMANDS):
        require(type(record) is dict and set(record) == {"label", "argv", "status", "inputs", "stdout", "stderr"}
                and record["label"] == label, "compiler-helper command order differs")
        require(type(record["argv"]) is list and bool(record["argv"])
                and all(type(item) is str and item for item in record["argv"]),
                "compiler-helper command argv differs")
        require(record["argv"] == _expected_command_argv(label, root=root, work=work, source_mount=source_mount),
                f"compiler-helper {label} argv differs")
        require(type(record["inputs"]) is list and same(record["inputs"], _expected_command_inputs(label, work)),
                f"compiler-helper {label} input relationship differs")
        require(type(record["status"]) is int, "compiler-helper command status is not an integer")
        if expected_status == "nonzero":
            require(record["status"] != 0, "compiler-helper archive-free link did not fail")
        else:
            require(record["status"] == expected_status, f"compiler-helper {label} did not pass")
        _resolve_work_identity(work, record["stdout"], f"{label} stdout")
        _resolve_work_identity(work, record["stderr"], f"{label} stderr")
        result.append(record)
    return result


def _event(events: Sequence[Mapping[str, Any]], label: str) -> Mapping[str, Any]:
    return next(item for item in events if item["label"] == label)


def _event_text(work: Path, events: Sequence[Mapping[str, Any]], label: str, stream: str) -> str:
    path = _resolve_work_identity(work, _event(events, label)[stream], f"{label} {stream}")
    return path.read_text(encoding="utf-8", errors="replace")


def _event_bytes(work: Path, events: Sequence[Mapping[str, Any]], label: str, stream: str) -> bytes:
    path = _resolve_work_identity(work, _event(events, label)[stream], f"{label} {stream}")
    return path.read_bytes()


def _ambient_link_input(trace: str) -> bool:
    """Reject a CRT/compiler-runtime input named by the retained link trace."""

    return re.search(r"libgcc|compiler-rt|libc\.a|/[Sr]?crt[^/\s]*\.o", trace) is not None


def _validate_aggregate_observations(work: Path, contract: Mapping[str, Any], events: Sequence[Mapping[str, Any]],
                                     artifacts: Mapping[str, Any]) -> dict[str, Any]:
    names = set(helper_names(contract))
    imports = {line.split()[-1] for line in _event_text(work, events, "candidate-imports", "stdout").splitlines()
               if line.split()}
    require(imports == names, "aggregate C object import roster differs")
    definitions = {line.split()[-1] for line in _event_text(work, events, "candidate-definitions", "stdout").splitlines()
                   if line.split()}
    require(names <= definitions, "aggregate candidate definition roster differs")
    require(not _event_text(work, events, "candidate-undefined", "stdout").strip(),
            "aggregate candidate retains undefined symbols")
    archive_free = _event_text(work, events, "archive-free-link", "stderr")
    require(all(name in archive_free for name in names), "archive-free link did not name every direct helper")
    candidate_link = _event_text(work, events, "candidate-link", "stdout")
    require(not _ambient_link_input(candidate_link),
            "aggregate candidate link admitted an ambient CRT or compiler runtime")
    header = _event_text(work, events, "candidate-header", "stdout")
    require("Type:                              EXEC (Executable file)" in header
            and "Advanced Micro Devices X86-64" in header, "aggregate candidate ELF header differs")
    program_headers = _event_text(work, events, "candidate-program-headers", "stdout")
    require("INTERP" not in program_headers and not re.search(r"\bTLS\b", program_headers),
            "aggregate candidate program headers admit an interpreter or TLS")
    dynamic = _event_text(work, events, "candidate-dynamic", "stdout")
    require(re.search(r"\((NEEDED|JMPREL|PLTGOT)\)", dynamic) is None,
            "aggregate candidate dynamic linkage differs")
    disassembly = _event_text(work, events, "candidate-disassembly", "stdout")
    direct = [name for name in names
              if re.search(r"(?:call|jmp)\S*\s+[^\n]*<" + re.escape(name) + r">", disassembly)]
    require(set(direct) == names, "aggregate candidate did not transfer to every helper")
    require(_event_bytes(work, events, "reference-execute", "stdout") == EXPECTED_TRANSCRIPT
            and _event_bytes(work, events, "candidate-execute", "stdout") == EXPECTED_TRANSCRIPT,
            "aggregate candidate/reference transcript differs")
    require(artifacts["aggregate.o"]["sha256"] != artifacts["pinned-musl-reference.o"]["sha256"],
            "aggregate candidate and reference objects unexpectedly share bytes")
    return {"candidate_object_direct_imports": list(helper_names(contract)),
            "candidate_archive_free_failure": list(helper_names(contract)),
            "candidate_static_elf": "ET_EXEC", "candidate_has_interpreter": False,
            "candidate_has_tls": False, "candidate_has_dynamic_dependencies": False,
            "candidate_has_ambient_compiler_runtime": False,
            "candidate_reference_same_object": False,
            "transcript": EXPECTED_TRANSCRIPT.decode("ascii")}


def _live_tool(command: Sequence[str], description: str) -> str:
    """Read a retained native artifact directly during replay.

    Command-event streams show how the runner invoked its pinned tools.  They
    are not a replacement for opening the retained archive and ET_EXEC again
    on the replay host.
    """

    try:
        completed = subprocess.run(list(command), check=True, text=True, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError) as error:
        raise CompilerHelperEvidenceError(f"cannot directly inspect retained {description}") from error
    return completed.stdout


def _complex_edge_commands(work: Path) -> tuple[tuple[str, list[str]], ...]:
    cc = ORACLE_CC
    archive = str(work / "libcrabc-builtins.a")
    return (
        ("build", ["python3", str(ROOT / BUILDER), "--output", archive,
                   "--provenance", str(work / "libcrabc-builtins.a.provenance.json"),
                   "--verify-reproducible"]),
        ("oracle-compile", [cc, "-std=c11", "-O2", "-fno-builtin", "-ffunction-sections",
                            "-I", str(work), "-include", "math.h",
                            "-D__mulsc3=crabc_reference_mulsc3",
                            "-D__muldc3=crabc_reference_muldc3",
                            "-D__mulxc3=crabc_reference_mulxc3", "-c",
                            str(ROOT / COMPLEX_EDGE_SOURCE), "-o", str(work / "complex-edge-oracle.o")]),
        ("probe-compile", [cc, "-std=c11", "-O2", "-fno-builtin", "-c",
                           str(work / "complex-edge-probe.c"), "-o", str(work / "complex-edge-probe.o")]),
        ("link", [cc, "-no-pie", "-Wl,--gc-sections", "-Wl,-t", str(work / "complex-edge-probe.o"),
                  str(work / "complex-edge-oracle.o"), archive, "-o", str(work / "complex-edge-candidate")]),
        ("execute", [str(work / "complex-edge-candidate")]),
    )


def _complex_edge_record(work: Path) -> dict[str, Any]:
    work = _physical_directory(work, "complex edge work")
    require((work / "libm.h").read_bytes() == b"", "complex edge private header differs")
    require((work / "complex-edge-probe.c").read_bytes() == COMPLEX_EDGE_PROBE.encode("ascii"),
            "complex edge probe source differs")
    artifacts = {name: _work_identity(work, work / name, "complex edge " + name)
                 for name in COMPLEX_EDGE_ARTIFACTS}
    commands = []
    for label, argv in _complex_edge_commands(work):
        stdout = work / "raw" / (label + ".stdout")
        stderr = work / "raw" / (label + ".stderr")
        require(stdout.is_file() and stderr.is_file(), "complex edge command stream is missing")
        commands.append({"label": label, "argv": argv, "status": 0,
                         "stdout": _work_identity(work, stdout, "complex edge " + label + " stdout"),
                         "stderr": _work_identity(work, stderr, "complex edge " + label + " stderr")})
    require(same(_read_json(work / "complex-edge-commands.json", "complex edge commands"), commands),
            "complex edge command record differs")
    require((work / "raw/execute.stdout").read_bytes() == COMPLEX_EDGE_TRANSCRIPT
            and (work / "raw/execute.stderr").read_bytes() == b"",
            "complex edge differential transcript differs")
    require(str(work / "libcrabc-builtins.a") in (work / "raw/link.stdout").read_text(encoding="utf-8"),
            "complex edge link did not retain the owned archive")
    archive = work / "libcrabc-builtins.a"
    contract = load_contract(ROOT)
    require(_nm_defined_names(archive) == set(helper_names(contract)),
            "complex edge archive roster differs")
    provenance = _provenance(work / "libcrabc-builtins.a.provenance.json", contract,
                             artifacts["libcrabc-builtins.a"])
    oracle_names = _nm_defined_names(work / "complex-edge-oracle.o")
    require("crabc_reference_muldc3" in oracle_names and "__muldc3" not in oracle_names,
            "complex edge source oracle definition differs")
    probe_imports = set(_live_tool(["nm", "--undefined-only", str(work / "complex-edge-probe.o")],
                                   "complex edge probe imports").split())
    require({"__muldc3", "crabc_reference_muldc3"} <= probe_imports,
            "complex edge probe does not import both implementations")
    candidate = work / "complex-edge-candidate"
    final_definitions = _nm_defined_names(candidate)
    require({"__muldc3", "crabc_reference_muldc3"} <= final_definitions,
            "complex edge final ELF definitions differ")
    header = _live_tool(["readelf", "-hW", str(candidate)], "complex edge final ELF header")
    require("Advanced Micro Devices X86-64" in header and "EXEC (Executable file)" in header,
            "complex edge final ELF target differs")
    disassembly = _live_tool(["objdump", "--disassemble", str(candidate)], "complex edge final ELF calls")
    for name in ("__muldc3", "crabc_reference_muldc3"):
        require(re.search(r"\bcall\S*\s+[^\n]*<" + name + r">", disassembly) is not None,
                "complex edge final ELF does not call " + name)
    return {"schema": COMPLEX_EDGE_SCHEMA, "target": TARGET, "cases": COMPLEX_EDGE_CASES,
            "source": [file_identity(ROOT, relative) for relative in
                       (SOURCE, BUILDER, CONTRACT, COMPLEX_EDGE_SOURCE, READER)],
            "compiler": _external_file_identity(Path(ORACLE_CC), "complex edge pinned musl compiler"),
            "artifacts": artifacts, "provenance": provenance, "commands": commands,
            "observations": {"owned_archive_retained": True, "distinct_source_oracle_retained": True,
                             "final_elf_direct_calls": ["__muldc3", "crabc_reference_muldc3"],
                             "signed_zero_compared_by_bits": True,
                             "transcript": COMPLEX_EDGE_TRANSCRIPT.decode("ascii")},
            "scope": "A pinned-musl differential fixture around the owned helper archive; not an installed candidate product."}


def collect_complex_edge_differential(work: Path) -> dict[str, Any]:
    """Run the bounded compiler-rt complex edge oracle in the pinned x86 image."""

    work = checkout_work_directory(ROOT, work)
    require(not work.exists() or (work.is_dir() and not work.is_symlink() and not any(work.iterdir())),
            "complex edge work directory must be fresh and empty")
    require(Path(ORACLE_CC).is_file(), "complex edge pinned musl compiler is unavailable")
    work.mkdir(parents=True, exist_ok=True)
    (work / "raw").mkdir()
    # Only public math macros are needed by the source translation here.
    (work / "libm.h").write_bytes(b"")
    (work / "complex-edge-probe.c").write_text(COMPLEX_EDGE_PROBE, encoding="ascii")
    commands = []
    for label, argv in _complex_edge_commands(work):
        result = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (work / "raw" / (label + ".stdout")).write_bytes(result.stdout)
        (work / "raw" / (label + ".stderr")).write_bytes(result.stderr)
        require(result.returncode == 0,
                f"complex edge {label} failed: {result.stderr.decode('utf-8', errors='replace')}")
        commands.append({"label": label, "argv": argv, "status": result.returncode,
                         "stdout": _work_identity(work, work / "raw" / (label + ".stdout"),
                                                  "complex edge " + label + " stdout"),
                         "stderr": _work_identity(work, work / "raw" / (label + ".stderr"),
                                                  "complex edge " + label + " stderr")})
    (work / "complex-edge-commands.json").write_text(canonical_json(commands), encoding="utf-8")
    report = _complex_edge_record(work)
    (work / "complex-edge-report.json").write_text(canonical_json(report), encoding="utf-8")
    return report


def validate_complex_edge_differential(report_path: Path) -> dict[str, Any]:
    report_path = _physical_file(report_path, "complex edge report")
    require(report_path.name == "complex-edge-report.json", "complex edge report name differs")
    report = _read_json(report_path, "complex edge report")
    require(type(report) is dict and type(report.get("artifacts")) is dict
            and type(report["artifacts"].get("complex-edge-candidate")) is dict,
            "complex edge candidate identity fields differ")
    _resolve_work_identity(report_path.parent, report["artifacts"]["complex-edge-candidate"],
                           "complex edge candidate identity")
    expected = _complex_edge_record(report_path.parent)
    require(same(report, expected), "complex edge report does not reconstruct")
    return report


def _nm_defined_names(path: Path) -> set[str]:
    return {line.split()[-1] for line in _live_tool(["nm", "--defined-only", "--extern-only", str(path)],
                                                     "compiler-helper symbol table").splitlines()
            if len(line.split()) >= 2 and not line.endswith(":" )}


def _live_artifact_observations(work: Path, contract: Mapping[str, Any], artifacts: Mapping[str, Any]) -> dict[str, Any]:
    """Bind archive/candidate identities to fresh ELF and symbol-table reads."""

    archive = _resolve_work_identity(work, artifacts["libcrabc-builtins.a"], "aggregate archive")
    candidate = _resolve_work_identity(work, artifacts["candidate"], "aggregate candidate")
    names = set(helper_names(contract))
    require(_nm_defined_names(archive) == names, "retained compiler-helper archive definition roster differs")
    archive_symbols = _live_tool(["readelf", "-sW", str(archive)], "compiler-helper archive ELF")
    rows: list[list[str]] = []
    for line in archive_symbols.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].endswith(":") and fields[3:6] == ["FUNC", "GLOBAL", "DEFAULT"]:
            rows.append(fields)
    helper_rows = [fields for fields in rows if fields[-1] in names]
    require(len(helper_rows) == len(names) and {fields[-1] for fields in helper_rows} == names
            and {fields[6] for fields in helper_rows}.isdisjoint({"UND", "ABS"}),
            "retained compiler-helper archive ELF metadata differs")
    require({fields[-1] for fields in rows} == names,
            "retained compiler-helper archive has an extra exported function")
    candidate_definitions = _nm_defined_names(candidate)
    require(names <= candidate_definitions, "retained aggregate candidate definitions differ")
    candidate_undefined = _live_tool(["nm", "--undefined-only", str(candidate)], "aggregate candidate undefined symbols")
    require(not candidate_undefined.strip(), "retained aggregate candidate has undefined symbols")
    header = _live_tool(["readelf", "-hW", str(candidate)], "aggregate candidate ELF header")
    program_headers = _live_tool(["readelf", "-lW", str(candidate)], "aggregate candidate program headers")
    dynamic = _live_tool(["readelf", "-dW", str(candidate)], "aggregate candidate dynamic section")
    disassembly = _live_tool(["objdump", "--disassemble", str(candidate)], "aggregate candidate disassembly")
    require("Type:                              EXEC (Executable file)" in header
            and "Advanced Micro Devices X86-64" in header, "retained aggregate candidate ELF header differs")
    require("INTERP" not in program_headers and not re.search(r"\bTLS\b", program_headers),
            "retained aggregate candidate has an interpreter or TLS")
    require(re.search(r"\((NEEDED|JMPREL|PLTGOT)\)", dynamic) is None,
            "retained aggregate candidate dynamic linkage differs")
    direct = {name for name in names
              if re.search(r"(?:call|jmp)\S*\s+[^\n]*<" + re.escape(name) + r">", disassembly)}
    require(direct == names, "retained aggregate candidate direct helper transfers differ")
    return {"archive": artifacts["libcrabc-builtins.a"], "candidate": artifacts["candidate"],
            "archive_global_default_functions": list(helper_names(contract)),
            "candidate_direct_transfers": list(helper_names(contract)), "candidate_elf_type": "EXEC",
            "candidate_has_interpreter": False, "candidate_has_tls": False,
            "candidate_has_dynamic_dependencies": False}


def _provenance(path: Path, contract: Mapping[str, Any], archive_identity: Mapping[str, Any]) -> dict[str, Any]:
    value = _read_json(path, "compiler-helper archive provenance")
    require(type(value) is dict and set(value) == {"schema", "target", "scope", "source", "contract", "archive", "reproducible"},
            "compiler-helper archive provenance fields differ")
    require(type(value["schema"]) is int and value["schema"] == 1 and type(value["target"]) is str
            and value["target"] == TARGET and type(value["scope"]) is str and bool(value["scope"])
            and type(value["source"]) is str and value["source"] == SOURCE.as_posix()
            and type(value["contract"]) is str and value["contract"] == CONTRACT.as_posix()
            and value["reproducible"] is True, "compiler-helper archive provenance boundary differs")
    archive = value["archive"]
    require(type(archive) is dict and archive.get("members") == [ARCHIVE_MEMBER]
            and type(archive.get("defined_symbols")) is list
            and set(archive["defined_symbols"]) == set(helper_names(contract))
            and len(archive["defined_symbols"]) == len(helper_names(contract))
            and type(archive.get("archive_sha256")) is str
            and re.fullmatch(r"[0-9a-f]{64}", archive["archive_sha256"]) is not None
            and archive["archive_sha256"] == archive_identity.get("sha256")
            and same(archive.get("contract"), contract), "compiler-helper archive provenance roster differs")
    return value


def _aggregate_artifacts(work: Path) -> dict[str, Any]:
    return {name: _work_identity(work, work / name, "aggregate " + name) for name in AGGREGATE_ARTIFACTS}


def _aggregate_record(work: Path, source_before: Path, events_path: Path, *, image: str,
                      source_mount: str, oracle_record: Path, root: Path,
                      verify_oracle_current: bool) -> dict[str, Any]:
    require(type(image) is str and IMAGE_PATTERN.fullmatch(image) is not None,
            "compiler-helper pinned image identity differs")
    contract = load_contract(root)
    before = _source_seal(source_before, root=root)
    current = source_binding(root, contract)
    current_checkout = _checkout_identity(root)
    current_product_source = _product_source_identity(root)
    require(same(before["source"], current) and same(before["checkout"], current_checkout)
            and same(before["product_source"], current_product_source),
            "compiler-helper source changed during aggregate execution")
    require(source_mount == SOURCE_MOUNT, "compiler-helper source mount differs")
    events = _command_events(work, events_path, root=root, source_mount=source_mount)
    artifacts = _aggregate_artifacts(work)
    oracle = _oracle_compiler_record(work, oracle_record, verify_current=verify_oracle_current)
    provenance = _provenance(work / "libcrabc-builtins.a.provenance.json", contract,
                             artifacts["libcrabc-builtins.a"])
    observations = _validate_aggregate_observations(work, contract, events, artifacts)
    live_artifacts = _live_artifact_observations(work, contract, artifacts)
    return {
        "schema": AGGREGATE_SCHEMA,
        "status": "compiler-helper-aggregate-evidence-unqualified",
        "target": TARGET,
        "image": image,
        "source_mount": source_mount,
        "oracle_compiler": oracle,
        "source_before": before["source"],
        "source_after": current,
        "checkout_before": before["checkout"],
        "checkout_after": current_checkout,
        "product_source_before": before["product_source"],
        "product_source_after": current_product_source,
        "contract": contract,
        "artifacts": artifacts,
        "provenance": _work_identity(work, work / "libcrabc-builtins.a.provenance.json", "aggregate provenance"),
        "commands": events,
        "observations": observations,
        "live_artifacts": live_artifacts,
        "limits": [
            "The candidate and pinned-musl reference use distinct compiled objects; no same-object claim is made.",
            "This fresh archive proof does not select same-named candidate-shared placements.",
            "Installed static-builtins/dynamic-builtins and the one ordinary __popcountdi2 product import require fresh supplied-product receipts.",
            "This component is not family completion, runtime qualification, promotion, or public support.",
        ],
        "family_completion": False,
        "public_support": False,
    }


def write_aggregate_report(output: Path, *, work: Path, source_before: Path, events_path: Path, image: str,
                           source_mount: str, oracle_record: Path,
                           root: Path = ROOT) -> dict[str, Any]:
    output = Path(output).absolute()
    work = _physical_directory(work, "compiler-helper work")
    require(output.parent == work and output.name == "report.json" and not output.exists()
            and not output.is_symlink(), "compiler-helper aggregate report output differs")
    record = _aggregate_record(work, source_before, events_path, image=image, source_mount=source_mount,
                               oracle_record=oracle_record, root=Path(root).absolute(), verify_oracle_current=True)
    output.write_text(canonical_json(record), encoding="utf-8")
    return record


def validate_aggregate_report(report_path: Path, *, root: Path = ROOT) -> dict[str, Any]:
    report_path = _physical_file(report_path, "compiler-helper aggregate report")
    require(report_path.name == "report.json", "compiler-helper aggregate report name differs")
    work = _physical_directory(report_path.parent, "compiler-helper work")
    report = _read_json(report_path, "compiler-helper aggregate report")
    require(type(report) is dict and type(report.get("image")) is str and type(report.get("source_mount")) is str,
            "compiler-helper aggregate report image differs")
    expected = _aggregate_record(work, work / "source-before.json", work / "commands.json",
                                 image=report["image"], source_mount=report["source_mount"],
                                 oracle_record=work / "oracle-compiler.json", root=Path(root).absolute(),
                                 verify_oracle_current=False)
    require(same(report, expected), "compiler-helper aggregate report does not reconstruct")
    return report


def validate_source_seal(source_path: Path, *, root: Path = ROOT) -> dict[str, Any]:
    """Replay a source-only seal before a separate product reader consumes it."""

    return _source_seal(source_path, root=Path(root).absolute())

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.allow_abbrev = False
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture-source", allow_abbrev=False)
    capture.add_argument("--output", required=True, type=Path)
    oracle_capture = commands.add_parser("capture-oracle-compiler", allow_abbrev=False)
    oracle_capture.add_argument("--work", required=True, type=Path)
    oracle_capture.add_argument("--output", required=True, type=Path)
    oracle_capture.add_argument("--compiler", required=True, type=Path)
    append = commands.add_parser("append-command", allow_abbrev=False)
    append.add_argument("--work", required=True, type=Path)
    append.add_argument("--events", required=True, type=Path)
    append.add_argument("--label", required=True)
    append.add_argument("--status", required=True, type=int)
    append.add_argument("--stdout", required=True, type=Path)
    append.add_argument("--stderr", required=True, type=Path)
    append.add_argument("--input", type=Path, action="append", default=[])
    append.add_argument("argv", nargs=argparse.REMAINDER)
    write = commands.add_parser("write-aggregate-report", allow_abbrev=False)
    write.add_argument("--work", required=True, type=Path)
    write.add_argument("--source-before", required=True, type=Path)
    write.add_argument("--events", required=True, type=Path)
    write.add_argument("--output", required=True, type=Path)
    write.add_argument("--image", required=True)
    write.add_argument("--source-mount", required=True)
    write.add_argument("--oracle-record", required=True, type=Path)
    replay = commands.add_parser("validate-aggregate-report", allow_abbrev=False)
    replay.add_argument("report", type=Path)
    source_replay = commands.add_parser("validate-source-seal", allow_abbrev=False)
    source_replay.add_argument("source", type=Path)
    complex_collect = commands.add_parser("collect-complex-edge-differential", allow_abbrev=False)
    complex_collect.add_argument("--work", required=True, type=Path)
    complex_replay = commands.add_parser("validate-complex-edge-differential", allow_abbrev=False)
    complex_replay.add_argument("report", type=Path)
    work_directory = commands.add_parser("validate-work-dir", allow_abbrev=False)
    work_directory.add_argument("--root", required=True, type=Path)
    work_directory.add_argument("--work", required=True, type=Path)
    work_directory.add_argument("--product", type=Path)
    product_admission = commands.add_parser("validate-materialized-product", allow_abbrev=False)
    product_admission.add_argument("--root", required=True, type=Path)
    product_admission.add_argument("--product", required=True, type=Path)
    fixture_write = commands.add_parser("write-fixture-report", allow_abbrev=False)
    fixture_write.add_argument("--output", required=True, type=Path)
    fixture_replay = commands.add_parser("validate-fixture-report", allow_abbrev=False)
    fixture_replay.add_argument("report", type=Path)
    products = commands.add_parser("validate-supplied-products", allow_abbrev=False)
    products.add_argument("--base-inventory", required=True, type=Path)
    products.add_argument("--elf-report", required=True, type=Path)
    products.add_argument("--static-preparation", required=True, type=Path)
    products.add_argument("--static-product", required=True, type=Path)
    products.add_argument("--dynamic-product", required=True, type=Path)
    products.add_argument("--ordinary-link-report", type=Path)
    products.add_argument("--aggregate-report", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "capture-source":
            capture_source(args.output)
            print("compiler-helper source seal written")
        elif args.command == "capture-oracle-compiler":
            capture_oracle_compiler(args.output, work=args.work, compiler=args.compiler)
            print("compiler-helper pinned musl compiler retained")
        elif args.command == "append-command":
            actual = args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv
            append_command_event(args.events, work=args.work, label=args.label, status=args.status,
                                 stdout=args.stdout, stderr=args.stderr, argv=actual, inputs=args.input)
            print("compiler-helper command event appended")
        elif args.command == "write-aggregate-report":
            write_aggregate_report(args.output, work=args.work, source_before=args.source_before,
                                   events_path=args.events, image=args.image, source_mount=args.source_mount,
                                   oracle_record=args.oracle_record)
            print("compiler-helper aggregate report written")
        elif args.command == "validate-aggregate-report":
            validate_aggregate_report(args.report)
            print("compiler-helper aggregate receipt valid; supplied-product placement proof remains separate")
        elif args.command == "validate-source-seal":
            validate_source_seal(args.source)
            print("compiler-helper source seal valid")
        elif args.command == "collect-complex-edge-differential":
            collect_complex_edge_differential(args.work)
            print("compiler-helper complex edge differential valid")
        elif args.command == "validate-complex-edge-differential":
            validate_complex_edge_differential(args.report)
            print("compiler-helper complex edge differential receipt valid")
        elif args.command == "validate-work-dir":
            print(checkout_work_directory(args.root, args.work, product=args.product))
        elif args.command == "validate-materialized-product":
            print(validate_materialized_dynamic_product(args.root, args.product))
        elif args.command == "write-fixture-report":
            contract = load_contract(ROOT)
            write_fixture_report(args.output, contract=contract, source=source_binding(ROOT, contract))
            print("compiler-helper source fixture receipt written")
        elif args.command == "validate-supplied-products":
            value = validate_supplied_product_evidence(
                root=ROOT, base_inventory=args.base_inventory, elf_report=args.elf_report,
                static_preparation=args.static_preparation, static_product=args.static_product,
                dynamic_product=args.dynamic_product, ordinary_link_report=args.ordinary_link_report,
                aggregate_report=args.aggregate_report,
            )
            print("compiler-helper supplied product evidence valid; shared placement remains unselected"
                  f"; ordinary-popcount={'present' if value['ordinary_popcount_import'] else 'absent'}")
        else:
            validate_fixture_report(args.report)
            print("compiler-helper source fixture receipt valid; product collection remains separate")
    except CompilerHelperEvidenceError as error:
        parser.exit(1, f"compiler-helper evidence failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
