#!/usr/bin/env python3
"""Assess the pinned normal-release x86-64 source API against ELF symbols.

This gate consumes a *passed* report from ``x86_64_release_evidence.py``.  It
does not compile or execute anything itself: the release report is the native
proof of the selected Linux/x86-64 mode and its two symbol inventories.  Each
source-declared C function is classified by object and dynamic-symbol
presence.  Header source forms that cannot be ELF function symbols (types,
macros, inline helpers, C++ source definitions, and option enumerators) are
recorded explicitly as ``not-an-object-symbol``.

The result is allocator-source evidence only.  It makes no claim about
behavior, Rust implementation coverage, crabc's public C API, or public x86
runtime support. Native provenance is the canonical launcher's attestation,
validated when the release report is made and again before this assessment is
written; this gate is not a hardware-attestation mechanism.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "compat/allocator/x86_64-api-native-coverage-v3.5.0.json"
RELEASE_REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/release-evidence.json"
REPORT_DEFAULT = ROOT / "compat/reports/allocator/x86_64/api-native-coverage.json"
RELEASE_SCRIPT_PATH = ROOT / "compat/allocator/x86_64_release_evidence.py"

_release_spec = importlib.util.spec_from_file_location(
    "crabc_x86_64_release_evidence_for_native_api", RELEASE_SCRIPT_PATH
)
assert _release_spec is not None and _release_spec.loader is not None
release_evidence = importlib.util.module_from_spec(_release_spec)
_release_spec.loader.exec_module(release_evidence)


class CoverageError(RuntimeError):
    """A release report or pinned source contract failed closed validation."""


EXPECTED_SCHEMA = "crabc-mimalloc-x86_64-api-native-coverage"
EXPECTED_TARGET = {
    "architecture": "x86_64",
    "endianness": "little",
    "system": "linux",
    "rust_target": "x86_64-unknown-linux-musl",
}
EXPECTED_UPSTREAM = {
    "archive_root": "mimalloc-3.5.0",
    "revision": "18b08671c9302247bfb682286e6bf3cc1773f801",
    "version": "3.5.0",
}
EXPECTED_PROFILE = "linux-x86_64-pinned-mimalloc-release"
EXPECTED_SCOPE = {
    "native_linux_x86_64_required": True,
    "release_mode_and_symbol_presence_only": True,
    "behavior_claimed": False,
    "rust_implementation_claimed": False,
    "public_crabc_support": False,
    "public_x86_libc_or_ldso_support": False,
    "public_runtime_or_api_compatibility": False,
    "aarch64_status_reused": False,
    "emulation_accepted": False,
}

FUNCTION_CLASSIFICATION = "object-symbol"
NOT_OBJECT_CLASSIFICATION = "not-an-object-symbol"
PRESENCE_VALUES = {"present", "absent"}

# These are source-form fields in x86_64-api-coverage-v3.5.0.json.  Their
# entries are source declarations/definitions, but are not standalone ELF
# object symbols for this C release API assessment.
NON_OBJECT_FIELDS = (
    "c_static_inline_functions",
    "c_type_aliases",
    "c_type_tags",
    "cxx_template_structures",
    "cxx_operator_source_definitions",
    "macro_definitions",
    "runtime_option_enumerators",
)


def _read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CoverageError(f"cannot read {description}: {path}") from error
    if not isinstance(value, dict):
        raise CoverageError(f"{description} is not a JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise CoverageError(f"cannot hash evidence report: {path}") from error


def exactly_matches(observed: object, expected: object) -> bool:
    """Compare JSON-shaped contracts without Python's bool/int coercion."""

    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(observed, dict)
        return set(observed) == set(expected) and all(
            exactly_matches(observed[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        assert isinstance(observed, list)
        return len(observed) == len(expected) and all(
            exactly_matches(actual, wanted) for actual, wanted in zip(observed, expected)
        )
    return observed == expected


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def load_schema() -> dict[str, Any]:
    """Validate this gate's fixed target and source-ledger contract."""

    value = _read_json(SCHEMA_PATH, "native API coverage schema")
    required = {
        "format",
        "schema",
        "profile",
        "target",
        "upstream",
        "scope",
        "source_inventories",
        "classification",
        "release_evidence",
    }
    if set(value) != required:
        raise CoverageError("native API coverage schema has unexpected fields")
    if type(value["format"]) is not int or value["format"] != 1 or value["schema"] != EXPECTED_SCHEMA:
        raise CoverageError("unsupported native API coverage schema")
    if value["profile"] != EXPECTED_PROFILE or not exactly_matches(value["target"], EXPECTED_TARGET):
        raise CoverageError("native API coverage schema target or profile drifted")
    if not exactly_matches(value["upstream"], EXPECTED_UPSTREAM):
        raise CoverageError("native API coverage schema upstream pin drifted")
    if not exactly_matches(value["scope"], EXPECTED_SCOPE):
        raise CoverageError("native API coverage scope boundary drifted")
    if not exactly_matches(
        value["classification"],
        {
            "function": FUNCTION_CLASSIFICATION,
            "non_object_source_form": NOT_OBJECT_CLASSIFICATION,
            "presence_values": ["present", "absent"],
        },
    ):
        raise CoverageError("native API coverage classification contract drifted")
    if not exactly_matches(
        value["release_evidence"],
        {
            "schema": "crabc-mimalloc-x86_64-release-object-symbol-evidence",
            "report_status": "passed",
            "report_path": "compat/reports/allocator/x86_64/release-evidence.json",
        },
    ):
        raise CoverageError("release evidence input contract drifted")
    inventories = value["source_inventories"]
    if not exactly_matches(
        inventories,
        {
            "base": {
                "path": "compat/allocator/x86_64-api-v3.5.0.json",
                "sha256": "1cfbdffb2d6dc6f6f984a48f83dcc68cdd679cca958027181eb9e74ebdb130bc",
                "declaration_count": 180,
                "declaration_names_sha256": "5a17248c61dccbb5abd9b8fe742a4243594793c125e229b2156a7f5172915975",
            },
            "statistics": {
                "path": "compat/allocator/x86_64-api-coverage-v3.5.0.json",
                "sha256": "6fe7353c76ed022957d47234d949ef61b378815702b7f7b1da8169da787906b4",
                "declaration_count": 15,
                "declaration_names_sha256": "9a9c4bf51cde6774f22488f0e92200d1909cc6bc688cc4b824aa3aa92020cdda",
            },
        },
    ):
        raise CoverageError("pinned source inventory contract drifted")
    return value


def _strict_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CoverageError(f"release report {field} is not a string list")
    if value != sorted(set(value)):
        raise CoverageError(f"release report {field} is not sorted and duplicate-free")
    return value


def _expected_release_selection(schema: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "source_set": schema["release_source_set"],
        "flags": schema["release_flags"],
        "compile_definitions": schema["compile_definitions"],
        "target_mode_assertions": schema["target_mode_assertions"],
    }


def validate_release_report(
    report: Mapping[str, Any],
    *,
    observed_provenance: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate report identity, release selection, source binding, and symbols.

    Returning normalized names makes it impossible for item generation to use
    an unvalidated or forged symbol list.
    """

    release_schema = release_evidence.load_schema()
    expected_fields = {
        "format",
        "schema",
        "status",
        "provenance",
        "target",
        "upstream",
        "profile",
        "release_selection",
        "build",
        "symbols",
        "source_declaration_inventory",
        "scope",
    }
    if set(report) != expected_fields:
        raise CoverageError("release report has unexpected or missing fields")
    if type(report["format"]) is not int or report["format"] != 1 or report["schema"] != release_schema["schema"]:
        raise CoverageError("release report is not the pinned release-evidence schema")
    if report["status"] != "passed":
        raise CoverageError("release report is not a passed native release report")
    if not exactly_matches(report["target"], EXPECTED_TARGET) or report["profile"] != EXPECTED_PROFILE:
        raise CoverageError("release report target or profile is not the exact x86_64 release")
    if not exactly_matches(
        report["upstream"],
        {
            **EXPECTED_UPSTREAM,
            "archive_sha256": "1e432f0559a4ab512143b9bff7a700541a2c8d4712b26a72de3e0222790da305",
        },
    ):
        raise CoverageError("release report upstream pin is forged or incorrect")
    provenance = report["provenance"]
    if not isinstance(provenance, dict) or provenance.get("execution_mode") != "native" or provenance.get("host_architecture") not in {"x86_64", "amd64"}:
        raise CoverageError("release report lacks native x86_64 provenance")
    if observed_provenance is not None and dict(provenance) != dict(observed_provenance):
        raise CoverageError("release report provenance does not match this native run")
    if not exactly_matches(report["release_selection"], _expected_release_selection(release_schema)):
        raise CoverageError("release report normal-release target/mode selection drifted")
    build = report["build"]
    if not isinstance(build, dict) or set(build) != {"shared_command", "mode_probe_command", "object_commands", "elf"}:
        raise CoverageError("release report build evidence is incomplete")
    if not exactly_matches(
        build["elf"],
        {
            "class": "ELF64",
            "endianness": "little",
            "machine": "Advanced Micro Devices X86-64",
        },
    ):
        raise CoverageError("release report ELF identity is not x86_64")
    symbols = report["symbols"]
    if not isinstance(symbols, dict) or set(symbols) != {
        "object_global_mi_inventory",
        "dynamic_default_visible_mi_inventory",
        "object_global_defined_mi",
        "dynamic_default_visible_mi",
    }:
        raise CoverageError("release report symbol evidence is incomplete")
    object_names = _strict_list(symbols["object_global_defined_mi"], "object_global_defined_mi")
    dynamic_names = _strict_list(symbols["dynamic_default_visible_mi"], "dynamic_default_visible_mi")
    object_inventory = release_schema["object_global_mi_symbol_inventory"]
    dynamic_inventory = release_schema["dynamic_default_visible_mi_symbol_inventory"]
    if not exactly_matches(symbols["object_global_mi_inventory"], object_inventory):
        raise CoverageError("release report object inventory metadata drifted")
    if not exactly_matches(symbols["dynamic_default_visible_mi_inventory"], dynamic_inventory):
        raise CoverageError("release report dynamic inventory metadata drifted")
    if len(object_names) != object_inventory["count"] or release_evidence.symbol_digest(object_names) != object_inventory["sorted_names_sha256"]:
        raise CoverageError("release report object symbol list does not match the pinned inventory")
    try:
        source_inventory = release_evidence.load_source_symbol_inventory(release_schema)
    except release_evidence.EvidenceError as error:
        raise CoverageError(str(error)) from error
    if dynamic_names != source_inventory["expected_dynamic_names"]:
        raise CoverageError("release report dynamic symbols do not match the pinned source inventory")
    if len(dynamic_names) != dynamic_inventory["count"] or release_evidence.symbol_digest(dynamic_names) != dynamic_inventory["sorted_names_sha256"]:
        raise CoverageError("release report dynamic symbol list does not match the pinned inventory")
    expected_source_report = {
        "base_header": {key: value for key, value in source_inventory["base_header"].items() if key != "names"},
        "statistics_header": {key: value for key, value in source_inventory["statistics_header"].items() if key != "names"},
        "normal_release_exceptions": source_inventory["normal_release_exceptions"],
        "source_union_count": source_inventory["source_union_count"],
        "expected_dynamic_count": source_inventory["expected_dynamic_count"],
        "expected_dynamic_names_sha256": source_inventory["expected_dynamic_names_sha256"],
    }
    if not exactly_matches(report["source_declaration_inventory"], expected_source_report):
        raise CoverageError("release report source declaration inventory is forged or stale")
    if not exactly_matches(report["scope"], release_schema["scope"]):
        raise CoverageError("release report scope boundary drifted")
    return {"object": object_names, "dynamic": dynamic_names}, source_inventory


def _validate_source_ledger_hashes(native_schema: Mapping[str, Any]) -> None:
    inventories = native_schema["source_inventories"]
    for key, path in (
        ("base", release_evidence.SOURCE_API_PATH),
        ("statistics", release_evidence.SOURCE_COVERAGE_PATH),
    ):
        if sha256_file(path) != inventories[key]["sha256"]:
            raise CoverageError(f"pinned {key} source inventory file digest drifted")


def _function_items(source_inventory: Mapping[str, Any], symbols: Mapping[str, list[str]]) -> list[dict[str, Any]]:
    """Build one record per unique source-declared C function."""

    declarations: dict[str, list[dict[str, Any]]] = {}
    for surface, key in (("base-c-function", "base_header"), ("statistics-extension-function", "statistics_header")):
        for name in source_inventory[key]["names"]:
            declarations.setdefault(name, []).append({"surface": surface, "header": source_inventory[key]["path"]})
    records = []
    for name, declarations_for_name in declarations.items():
        records.append(
            {
                "id": f"c-function:{name}",
                "name": name,
                "kind": "source-declared-c-function",
                "declarations": declarations_for_name,
                "classification": FUNCTION_CLASSIFICATION,
                "object_symbol": "present" if name in symbols["object"] else "absent",
                "dynamic_symbol": "present" if name in symbols["dynamic"] else "absent",
            }
        )
    return records


def _non_object_items(native_schema: Mapping[str, Any]) -> list[dict[str, Any]]:
    _validate_source_ledger_hashes(native_schema)
    coverage = _read_json(release_evidence.SOURCE_COVERAGE_PATH, "source API coverage ledger")
    records: list[dict[str, Any]] = []
    for header in coverage["header_surfaces"]:
        member = header["member"]
        for field in NON_OBJECT_FIELDS:
            entries = header[field]
            for index, entry in enumerate(entries):
                if field == "cxx_operator_source_definitions":
                    name = f"operator {entry['operator']}"
                    line = entry["source_line"]
                else:
                    name = entry.get("name")
                    line = entry.get("source_line", entry.get("source_lines"))
                if not isinstance(name, str):
                    raise CoverageError(f"source form {member}:{field} has no stable name")
                records.append(
                    {
                        "id": f"source-form:{member}:{field}:{index}:{name}",
                        "name": name,
                        "kind": field,
                        "header": member,
                        "source_line": line,
                        "classification": NOT_OBJECT_CLASSIFICATION,
                        "object_symbol": NOT_OBJECT_CLASSIFICATION,
                        "dynamic_symbol": NOT_OBJECT_CLASSIFICATION,
                    }
                )
    return records


def assess(
    report: Mapping[str, Any], *, observed_provenance: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """Validate evidence and return the deterministic API assessment."""

    native_schema = load_schema()
    symbols, source_inventory = validate_release_report(
        report, observed_provenance=observed_provenance
    )
    items = _function_items(source_inventory, symbols) + _non_object_items(native_schema)
    function_count = len(_function_items(source_inventory, symbols))
    function_items = items[:function_count]
    non_object_items = items[function_count:]
    return {
        "format": 1,
        "schema": native_schema["schema"],
        "status": "passed",
        "target": EXPECTED_TARGET,
        "upstream": report["upstream"],
        "profile": EXPECTED_PROFILE,
        "provenance": report["provenance"],
        "normal_release_selection": report["release_selection"],
        "release_elf": report["build"]["elf"],
        "source_evidence": native_schema["source_inventories"],
        "scope": EXPECTED_SCOPE,
        "summary": {
            "source_declared_function_count": len(function_items),
            "object_symbol_function_present": sum(item["object_symbol"] == "present" for item in function_items),
            "dynamic_symbol_function_present": sum(item["dynamic_symbol"] == "present" for item in function_items),
            "not_an_object_symbol_item_count": len(non_object_items),
            "object_inventory_count": len(symbols["object"]),
            "dynamic_inventory_count": len(symbols["dynamic"]),
        },
        "items": items,
    }


def build(*, release_report_path: Path, report_path: Path, offline: bool = False) -> dict[str, Any]:
    """Run the native gate and write one report; ``offline`` is API-compatible."""

    del offline
    try:
        provenance = release_evidence.require_native_x86_64()
    except release_evidence.EvidenceError as error:
        raise CoverageError(str(error)) from error
    release_report = _read_json(release_report_path, "native release evidence report")
    result = assess(release_report, observed_provenance=provenance)
    result["evidence_inputs"] = {
        "release_report": {"path": relative(release_report_path), "sha256": sha256_file(release_report_path)},
        "source_schema": relative(SCHEMA_PATH),
    }
    release_evidence.run.write_json(report_path, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-report", type=Path, default=RELEASE_REPORT_DEFAULT)
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT)
    args = parser.parse_args()
    try:
        build(release_report_path=args.release_report, report_path=args.report)
    except (CoverageError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=os.sys.stderr)
        return 2
    print(args.report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
