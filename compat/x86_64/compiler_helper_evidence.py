#!/usr/bin/env python3
"""Read finite native compiler-helper archive ownership evidence.

This component owns the producer contract for the Rust-only x86 helper archive.
It does not build a sysroot, choose a same-named shared-libc placement, or turn
an archive definition into a public runtime export.  A later collector supplies
fresh, source-matched product and complete-ELF receipts to the helpers below.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = Path("builtins/x86_64-helper-contract.toml")
SOURCE = Path("builtins/src/lib.rs")
BUILDER = Path("builtins/build_x86_64.py")
AGGREGATE_PROBE = Path("builtins/fixtures/x86_64_compiler_helper_aggregate_probe.c")
AGGREGATE_START = Path("builtins/fixtures/x86_64_compiler_helper_aggregate_start.S")
AGGREGATE_RUNNER = Path("builtins/run_x86_64_compiler_helper_aggregate.sh")
SELECTION = Path("compat/x86_64/native-abi-selection.toml")
READER = Path("compat/x86_64/compiler_helper_evidence.py")
DOCUMENTATION = Path("builtins/x86_64-helper-contract.md")
SELECTION_DOCUMENTATION = Path("compat/x86_64/native-abi-selection.md")
SOURCE_FILES = (CONTRACT, SOURCE, BUILDER, AGGREGATE_PROBE, AGGREGATE_START, AGGREGATE_RUNNER, READER, SELECTION,
                DOCUMENTATION, SELECTION_DOCUMENTATION)
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
HELPER_ABIS = {
    "complex-double", "u128-binary", "u128-bit-count", "u128-byte-swap",
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


def validate_contract(value: object) -> dict[str, Any]:
    """Validate exact finite source ownership, never infer a prefix roster."""

    require(type(value) is dict and set(value) == {
        "schema", "target", "owner_group", "source", "builder", "producer_scope", "archive", "helpers",
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
    helpers = value["helpers"]
    require(type(helpers) is list and len(helpers) == 23, "compiler-helper helper roster differs")
    result: list[dict[str, Any]] = []
    names: list[str] = []
    for row in helpers:
        require(type(row) is dict and set(row) == {"name", "rust_signature", "c_abi", "caller_obligation", "metadata"},
                "compiler-helper helper record differs")
        name, signature, c_abi, obligation = row["name"], row["rust_signature"], row["c_abi"], row["caller_obligation"]
        require(type(name) is str and re.fullmatch(r"__[a-z0-9]+", name) is not None,
                "compiler-helper name differs")
        require(type(signature) is str and signature.startswith('pub ') and f"fn {name}" in signature,
                "compiler-helper Rust signature differs")
        require(type(c_abi) is str and c_abi in HELPER_ABIS and type(obligation) is str and obligation,
                "compiler-helper C ABI role differs")
        result.append({"name": name, "rust_signature": signature, "c_abi": c_abi,
                       "caller_obligation": obligation, "metadata": _helper_metadata(row["metadata"])})
        names.append(name)
    require(names == sorted(names) and len(names) == len(set(names)), "compiler-helper helper roster differs")
    return {"schema": 1, "target": TARGET, "owner_group": value["owner_group"], "source": value["source"],
            "builder": value["builder"], "producer_scope": value["producer_scope"], "archive": dict(archive),
            "helpers": result}


def load_contract(root: Path = ROOT) -> dict[str, Any]:
    raw = _read_toml(root)
    helpers = raw.get("helpers") if type(raw) is dict else None
    require(type(helpers) is list and all(type(row) is dict and type(row.get("metadata")) is dict
            and row["metadata"].get("version") == "unversioned" for row in helpers),
            "compiler-helper producer contract must spell unversioned metadata")
    return validate_contract(raw)


def helper_names(contract: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(row["name"] for row in contract["helpers"])


def source_definitions(root: Path = ROOT) -> dict[str, str]:
    """Read the direct no-mangle C definition set from Rust source bytes."""

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
    return result


def source_binding(root: Path, contract: Mapping[str, Any] | None = None) -> dict[str, Any]:
    root = Path(root).absolute()
    contract = load_contract(root) if contract is None else validate_contract(dict(contract))
    expected = {row["name"]: row["rust_signature"] for row in contract["helpers"]}
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
        receipt_path = work / record["receipt"].get("path", "")
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
        require(expected in map_text and re.search(r"\b__popcountdi2\b", map_text) is not None,
                f"ordinary-link {mode} map does not attribute __popcountdi2")
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
              "shared_placement_selected": False, "family_completion": False,
              "public_support": False}
    if ordinary_link_report is not None:
        try:
            import_join = _popcount_import_from_facts(facts, placements)
            ordinary_links = _ordinary_popcount_maps(root, Path(ordinary_link_report), ordinary_inputs)
        except CompilerHelperEvidenceError:
            raise
        except (ordinary.PublicDataEvidenceError, OSError, ValueError) as error:
            raise CompilerHelperEvidenceError("supplied ordinary __popcountdi2 evidence is not current and valid") from error
        result["ordinary_popcount_import"] = {**import_join, "ordinary_links": ordinary_links}
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
    require(not re.search(r"libgcc|compiler-rt|libc\.a|/crt[^[:space:]]*\.o", candidate_link),
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
