#!/usr/bin/env python3
"""Validate finite, non-promoting installed native loader-family evidence.

This coordinator does not run a loader, rebuild a product, or turn an inventory
into runtime evidence.  It joins one complete three-product dynamic
qualification with the corresponding three retained loader inventories.  The
qualification remains the semantic owner of its complete current dynamic-case
roster (including
all 21 synthetic and 34 frozen package-corpus cases); the inventories bind the
installed loader, libc, source provenance, retained musl capture, and readelf
capture for each exact product.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import sys
import tomllib
from typing import Any, Mapping

import owned_dynamic_qualification as qualification
import owned_loader_corpus_evidence as corpus_evidence
import owned_loader_inventory as inventory

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-loader-family/v1"
ROSTER_SCHEMA = "crabc.x86_64-owned-loader-family-roster/v1"
ROSTER_PATH = ROOT / "compat/x86_64/loader-family.toml"
FAMILY = "ldso.dynamic-runtime"
PRODUCTS = ("installed", "second", "extracted")
CAPABILITIES = (
    "runtime.loader",
    "runtime.private-facades",
    "loader.dlfcn-basic",
    "loader.dlfcn-introspection",
)
NONPROMOTING_FLAGS = {
    "component_complete": True,
    "family_completion": False,
    "promotion_ready": False,
    "public_support": False,
}

# These are the finite behavior boundaries of the Loader row in plan.md
# (Families and public ABI).  The catalog rows below obtain their exact
# current case IDs from the frozen runners instead of copying a second list
# here.  A new runner case consequently remains required by the
# full qualification and makes a stale behavior roster reject until reviewed.
EXPECTED_ROWS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("entry-and-initial-graph", "runtime.loader", ("cycle", "cli")),
    ("search-mapping-protection", "runtime.loader", ("cli", "elf-scope-alias", "lazy-pie", "lazy-non-pie", "loader-synthetic")),
    ("relocation-symbol-scope-relr", "runtime.loader", ("elf-scope-alias", "lazy-pie", "lazy-non-pie", "loader-synthetic")),
    ("runtime-v1-tls-thread", "runtime.private-facades", ("cycle", "dlopen-pie", "dlopen-non-pie", "pthread-exit", "pthread-signal", "loader-synthetic")),
    ("constructor-finalization", "runtime.loader", ("constructor-exit", "dlopen-pie", "dlopen-non-pie")),
    ("dlfcn-basic", "loader.dlfcn-basic", ("dlopen-pie", "dlopen-non-pie", "lazy-pie", "lazy-non-pie")),
    ("dlfcn-introspection", "loader.dlfcn-introspection", ("dlopen-pie", "dlopen-non-pie")),
    ("fork-callback-rollback", "runtime.private-facades", ("fork", "signal-handler-fork", "atfork-registry", "dlopen-pie", "dlopen-non-pie", "lazy-pie", "lazy-non-pie")),
    ("synthetic-loader-catalog", "runtime.loader", ("loader-synthetic",)),
    ("frozen-package-corpus", "runtime.loader", ("package-corpus",)),
)


class LoaderFamilyError(RuntimeError):
    """A selected receipt, sealed input, or behavior roster is incomplete."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LoaderFamilyError(message)


def same_json(left: object, right: object) -> bool:
    """Compare retained JSON without Python's bool/int or int/float aliases."""

    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(
        right, sort_keys=True, separators=(",", ":"), allow_nan=False,
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LoaderFamilyError(f"JSON object repeats {key!r}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise LoaderFamilyError(f"non-finite JSON constant: {value}")


def _digest(path: Path, description: str) -> str:
    require(path.is_file() and not path.is_symlink(), f"{description} is not a physical file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _physical_under(root: Path, value: Path, description: str, *, directory: bool | None = None) -> Path:
    """Return one physical checkout-local evidence path without aliasing it."""

    root = root.absolute()
    candidate = value if value.is_absolute() else root / value
    candidate = candidate.absolute()
    require(candidate.is_relative_to(root / ".work"), f"{description} must remain below checkout .work")
    try:
        details = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise LoaderFamilyError(f"{description} is missing or unsafe: {candidate}") from error
    require(resolved == candidate and not candidate.is_symlink(), f"{description} is not physical")
    if directory is True:
        require(stat.S_ISDIR(details.st_mode), f"{description} is not a directory")
    elif directory is False:
        require(stat.S_ISREG(details.st_mode), f"{description} is not a regular file")
    return candidate


def _relative_work(root: Path, value: object, description: str, *, directory: bool | None = False) -> Path:
    require(isinstance(value, str) and value and not Path(value).is_absolute() and ".." not in Path(value).parts,
            f"{description} must be a checkout-relative path")
    return _physical_under(root, Path(value), description, directory=directory)


def _identity(root: Path, path: Path, description: str) -> dict[str, Any]:
    path = _physical_under(root, path, description, directory=False)
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": _digest(path, description),
        "size": path.stat().st_size,
    }


def _read(root: Path, path: Path, description: str) -> dict[str, Any]:
    path = _physical_under(root, path, description, directory=False)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs, parse_constant=_invalid_constant)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LoaderFamilyError(f"{description} is not valid JSON") from error
    require(isinstance(value, dict), f"{description} must be an object")
    return value


def _source_identity(root: Path, path: Path, description: str) -> dict[str, Any]:
    path = path.absolute()
    try:
        details = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise LoaderFamilyError(f"{description} is missing or unsafe") from error
    require(resolved == path and stat.S_ISREG(details.st_mode) and not path.is_symlink()
            and path.is_relative_to(root), f"{description} is not a physical source file")
    return {"path": path.relative_to(root).as_posix(), "sha256": _digest(path, description), "size": path.stat().st_size}


def _loader_cases() -> tuple[str, ...]:
    cases = tuple(corpus_evidence.LOADER_CASES)
    require(cases and len(cases) == len(set(cases)), "synthetic loader roster is invalid")
    return cases


def _corpus_cases() -> tuple[str, ...]:
    cases = tuple(case.id for case in corpus_evidence._corpus_cases())
    require(cases and len(cases) == len(set(cases)), "package corpus roster is invalid")
    return cases


def _string_list(value: object, description: str) -> tuple[str, ...]:
    require(isinstance(value, list) and all(isinstance(item, str) and item for item in value),
            f"{description} must be a string list")
    items = tuple(value)
    require(len(items) == len(set(items)), f"{description} repeats a case")
    return items


def load_roster(path: Path = ROSTER_PATH) -> dict[str, Any]:
    """Load the behavior map and reject any silent coverage redirection."""

    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise LoaderFamilyError(f"cannot read loader family roster: {error}") from error
    require(isinstance(raw, dict) and set(raw) == {"schema", "family", "capabilities", "required"},
            "loader family roster fields differ")
    require(raw["schema"] == ROSTER_SCHEMA and raw["family"] == FAMILY,
            "loader family roster identity differs")
    require(tuple(raw["capabilities"]) == CAPABILITIES, "loader family capabilities differ")
    rows = raw["required"]
    require(isinstance(rows, list) and len(rows) == len(EXPECTED_ROWS), "loader family behavior count differs")
    synthetic = _loader_cases()
    corpus = _corpus_cases()
    qualification_cases = set(qualification.CASES)
    observed_ids: list[str] = []
    synthetic_seen: list[str] = []
    corpus_seen: list[str] = []
    normalized: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        require(isinstance(row, dict) and set(row) == {
            "id", "capability", "qualification_cases", "synthetic_cases", "package_cases", "behavior",
        }, "loader family behavior fields differ")
        identifier, capability, expected_qualification = EXPECTED_ROWS[index]
        require(row["id"] == identifier and row["capability"] == capability,
                "loader family behavior identity differs")
        require(isinstance(row["behavior"], str) and row["behavior"], "loader family behavior prose differs")
        selected = _string_list(row["qualification_cases"], identifier + " qualification")
        require(selected == expected_qualification and set(selected) <= qualification_cases,
                "loader family qualification behavior map differs")
        selected_synthetic = _string_list(row["synthetic_cases"], identifier + " synthetic")
        selected_corpus = _string_list(row["package_cases"], identifier + " package")
        if identifier == "synthetic-loader-catalog":
            require(selected_synthetic == synthetic and not selected_corpus,
                    "loader family synthetic catalog differs")
        elif identifier == "frozen-package-corpus":
            require(selected_corpus == corpus and not selected_synthetic,
                    "loader family package catalog differs")
        else:
            require(not selected_synthetic and not selected_corpus,
                    "loader family behavior redirects a frozen catalog")
        observed_ids.append(identifier)
        synthetic_seen.extend(selected_synthetic)
        corpus_seen.extend(selected_corpus)
        normalized.append({
            "id": identifier, "capability": capability, "qualification_cases": list(selected),
            "synthetic_cases": list(selected_synthetic), "package_cases": list(selected_corpus),
            "behavior": row["behavior"],
        })
    require(tuple(observed_ids) == tuple(row[0] for row in EXPECTED_ROWS), "loader family behavior roster order differs")
    require(tuple(synthetic_seen) == synthetic and tuple(corpus_seen) == corpus,
            "loader family frozen catalog coverage differs")
    return {"required": normalized}


def validate_request(root: Path, request: object) -> tuple[Path, dict[str, dict[str, Path]]]:
    require(isinstance(request, dict) and set(request) == {"schema", "qualification", "inventories"},
            "loader family request fields differ")
    require(request["schema"] == SCHEMA, "loader family request schema differs")
    qualification_path = _relative_work(root, request["qualification"], "dynamic qualification receipt")
    require(qualification_path.name == "qualification.json", "loader family requires qualification.json")
    inventories = request["inventories"]
    require(isinstance(inventories, dict) and set(inventories) == set(PRODUCTS),
            "loader family inventory product roster differs")
    selected: dict[str, dict[str, Path]] = {}
    for product in PRODUCTS:
        row = inventories[product]
        require(isinstance(row, dict) and set(row) == {"receipt", "oracle_capture", "readelf_capture"},
                "loader family inventory request fields differ")
        selected[product] = {
            field: _relative_work(root, row[field], f"{product} inventory {field}")
            for field in ("receipt", "oracle_capture", "readelf_capture")
        }
    return qualification_path, selected


def _qualification(root: Path, path: Path) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    try:
        record = qualification.validate_receipt(path)
    except (qualification.QualificationError, OSError, ValueError) as error:
        raise LoaderFamilyError(f"dynamic qualification differs: {error}") from error
    expected = {
        "schema", "status", "work", "source_sha256", "contracts", "products", "preparation", "cases",
        "base_evidence", "archives", "runtime_v1_published", "family_completion", "promotion_ready", "public_support",
    }
    require(isinstance(record, dict) and set(record) == expected
            and record["schema"] == qualification.SCHEMA and record["status"] == "qualified-pending-review",
            "dynamic qualification schema differs")
    require(isinstance(record["source_sha256"], str) and record["source_sha256"] == qualification.source_digest(),
            "dynamic qualification source differs")
    require(set(record["products"]) == set(PRODUCTS) and all(isinstance(record["products"][item], str) for item in PRODUCTS),
            "dynamic qualification product roster differs")
    require(all(record[name] is False for name in ("runtime_v1_published", "family_completion", "promotion_ready", "public_support")),
            "dynamic qualification promotion boundary differs")
    work = _relative_work(root, record["work"], "dynamic qualification work", directory=True)
    require(path == work / "qualification.json", "dynamic qualification receipt is not its retained root")
    preparation_path = _physical_under(root, work / "qualification-prepare.json", "qualification preparation", directory=False)
    preparation = _read(root, preparation_path, "qualification preparation")
    require(set(preparation) == {"schema", "source_sha256", "log", "log_sha256", "oracle", "checks", "exit_status"}
            and preparation["schema"] == qualification.SCHEMA and preparation["source_sha256"] == record["source_sha256"]
            and preparation["exit_status"] == 0 and isinstance(preparation["oracle"], dict),
            "qualification preparation differs")
    try:
        qualification.validate_oracle(work, preparation["oracle"])
    except (qualification.QualificationError, OSError, ValueError) as error:
        raise LoaderFamilyError(f"qualification prepared oracle differs: {error}") from error
    preparation_identity = _identity(root, preparation_path, "qualification preparation")
    require(record["preparation"].get(preparation_identity["path"]) == preparation_identity["sha256"],
            "qualification does not bind its preparation")
    cases = record["cases"]
    require(isinstance(cases, dict), "dynamic qualification case receipt map differs")
    expected_case_paths = {
        (work / "qualification-cases" / product / (case + ".json")).relative_to(root).as_posix()
        for product in PRODUCTS for case in qualification.CASES
    }
    require(set(cases) == expected_case_paths, "dynamic qualification is not the complete current case roster")
    return record, work, preparation["oracle"]


def _qualification_case_identity(root: Path, qualification_record: Mapping[str, Any], work: Path,
                                  product: str, case: str) -> dict[str, Any]:
    path = _physical_under(root, work / "qualification-cases" / product / (case + ".json"),
                           f"{product} qualification {case}", directory=False)
    identity = _identity(root, path, f"{product} qualification {case}")
    require(qualification_record["cases"].get(identity["path"]) == identity["sha256"],
            "dynamic qualification case input differs")
    return identity


def _inventory(root: Path, qualification_record: Mapping[str, Any], qualification_work: Path,
               prepared_oracle: Mapping[str, Any], product: str,
               selection: Mapping[str, Path]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    product_root = _physical_under(root, qualification_work / product, f"{product} qualification product", directory=True)
    try:
        record = inventory.validate_receipt(selection["receipt"], product_root, selection["oracle_capture"], selection["readelf_capture"])
        oracle_capture = inventory.supplied_oracle_capture(selection["oracle_capture"])
        readelf_capture = inventory.supplied_readelf_capture(selection["readelf_capture"])
    except (inventory.InventoryError, qualification.QualificationError, OSError, ValueError) as error:
        raise LoaderFamilyError(f"{product} inventory differs: {error}") from error
    require(isinstance(record, dict)
            and record.get("schema") == inventory.SCHEMA
            and record.get("component") == "native-x86-loader-inventory"
            and record.get("inventory_complete") is True
            and record.get("runtime_test_executed") is False
            and record.get("runtime_verified") is False,
            "inventory runtime boundary differs")
    capture = record.get("capture")
    require(isinstance(capture, dict) and same_json(capture.get("before"), capture.get("after")),
            "inventory capture boundary differs")
    before = capture["before"]
    require(isinstance(before, dict) and set(before) == {"product", "source", "oracle", "readelf"},
            "inventory capture fields differ")
    product_snapshot = before["product"]
    require(isinstance(product_snapshot, dict)
            and same_json(product_snapshot.get("root"), product_root.relative_to(root).as_posix())
            and same_json(product_snapshot.get("manifest_sha256"), qualification_record["products"][product]),
            "inventory selects another qualification product")
    source = before["source"]
    require(isinstance(source, dict) and same_json(source.get("source_sha256"), qualification_record["source_sha256"]),
            "inventory source differs from qualification")
    oracle = oracle_capture["identity"].get("oracle") if isinstance(oracle_capture.get("identity"), dict) else None
    require(same_json(oracle, prepared_oracle) and same_json(before["oracle"], oracle_capture),
            "inventory oracle differs from independently prepared qualification oracle")
    readelf = readelf_capture["identity"].get("readelf") if isinstance(readelf_capture.get("identity"), dict) else None
    require(same_json(before["readelf"], readelf_capture) and isinstance(readelf, dict),
            "inventory readelf capture differs")
    inputs = {field: _identity(root, selection[field], f"{product} inventory {field}")
              for field in ("receipt", "oracle_capture", "readelf_capture")}
    return record, inputs, product_snapshot, readelf


def _input_snapshot(root: Path, qualification_path: Path, selections: Mapping[str, Mapping[str, Path]]) -> dict[str, Any]:
    return {
        "qualification": _identity(root, qualification_path, "dynamic qualification receipt"),
        "inventories": {
            product: {field: _identity(root, values[field], f"{product} inventory {field}")
                      for field in ("receipt", "oracle_capture", "readelf_capture")}
            for product, values in selections.items()
        },
    }


def collect(root: Path, work: Path) -> dict[str, Any]:
    """Reconstruct a complete component report without executing any runtime."""

    root = root.absolute()
    work = _physical_under(root, work, "loader family work", directory=True)
    request_path = _physical_under(root, work / "request.json", "loader family request", directory=False)
    request_before = _identity(root, request_path, "loader family request")
    request = _read(root, request_path, "loader family request")
    source_before = qualification.source_digest()
    roster = load_roster()
    roster_identity = _source_identity(root, ROSTER_PATH, "loader family roster")
    qualification_path, selections = validate_request(root, request)
    inputs_before = _input_snapshot(root, qualification_path, selections)
    qualification_record, qualification_work, prepared_oracle = _qualification(root, qualification_path)
    require(qualification_record["source_sha256"] == source_before, "source changed before loader family collection")

    inventories: dict[str, dict[str, Any]] = {}
    readelf_before: dict[str, Any] | None = None
    for product in PRODUCTS:
        inventory_record, inputs, product_snapshot, readelf = _inventory(
            root, qualification_record, qualification_work, prepared_oracle, product, selections[product],
        )
        if readelf_before is None:
            readelf_before = readelf
        require(same_json(readelf, readelf_before), "inventories use different readelf tools")
        inventories[product] = {"record": inventory_record, "product": product_snapshot, "inputs": inputs}
    require(readelf_before is not None, "loader family has no readelf identity")

    coverage: dict[str, Any] = {}
    for row in roster["required"]:
        cells: dict[str, Any] = {}
        for product in PRODUCTS:
            cells[product] = {
                "product": inventories[product]["product"],
                "qualification_cases": {
                    case: _qualification_case_identity(root, qualification_record, qualification_work, product, case)
                    for case in row["qualification_cases"]
                },
                "inventory": inventories[product]["inputs"],
            }
        coverage[row["id"]] = {
            "capability": row["capability"], "behavior": row["behavior"],
            "synthetic_cases": row["synthetic_cases"], "package_cases": row["package_cases"], "cells": cells,
        }

    # A receipt hash alone cannot seal its reached tree.  Reuse each owner at
    # the end, so a changed case log, package payload, raw readelf stream or
    # product file cannot survive merely because its outer JSON was untouched.
    qualification_after, qualification_work_after, prepared_oracle_after = _qualification(root, qualification_path)
    require(same_json(qualification_record, qualification_after)
            and qualification_work == qualification_work_after
            and same_json(prepared_oracle, prepared_oracle_after),
            "dynamic qualification changed during loader family collection")
    readelf_after: dict[str, Any] | None = None
    for product in PRODUCTS:
        record_after, inputs_after_inventory, product_after, tool_after = _inventory(
            root, qualification_after, qualification_work_after, prepared_oracle_after, product, selections[product],
        )
        initial = inventories[product]
        require(same_json(initial["record"], record_after)
                and same_json(initial["inputs"], inputs_after_inventory)
                and same_json(initial["product"], product_after),
                f"{product} inventory changed during loader family collection")
        if readelf_after is None:
            readelf_after = tool_after
        require(same_json(tool_after, readelf_after), "inventories use different readelf tools after collection")
    require(readelf_after is not None and same_json(readelf_before, readelf_after),
            "readelf tool changed during loader family collection")

    source_after = qualification.source_digest()
    request_after = _identity(root, request_path, "loader family request")
    inputs_after = _input_snapshot(root, qualification_path, selections)
    require(same_json(source_before, source_after), "source changed during loader family collection")
    require(same_json(request_before, request_after), "request changed during loader family collection")
    require(same_json(inputs_before, inputs_after), "input changed during loader family collection")
    return {
        "schema": SCHEMA,
        "status": "installed-loader-component-verified",
        "family": FAMILY,
        "request": {"before": request_before, "after": request_after},
        "roster": roster_identity,
        "source": {"before": source_before, "after": source_after},
        "inputs": {"before": inputs_before, "after": inputs_after},
        "oracle": prepared_oracle,
        "tools": {"before": readelf_before, "after": readelf_after},
        "coverage": coverage,
        **NONPROMOTING_FLAGS,
    }


def _write_new(root: Path, path: Path, value: dict[str, Any]) -> None:
    path = _physical_under(root, path.parent, "loader family output parent", directory=True) / path.name
    require(path.name == "receipt.json" and not path.exists() and not path.is_symlink(),
            "loader family receipt must be a fresh receipt.json")
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
    path.chmod(0o444)


def execute(root: Path, work: Path) -> Path:
    work = _physical_under(root, work, "loader family work", directory=True)
    path = work / "receipt.json"
    _write_new(root, path, collect(root, work))
    return path


def validate_receipt(root: Path, path: Path) -> dict[str, Any]:
    path = _physical_under(root, path, "loader family receipt", directory=False)
    require(path.name == "receipt.json", "loader family receipt must be named receipt.json")
    observed = collect(root, path.parent)
    require(same_json(_read(root, path, "loader family receipt"), observed), "loader family receipt changed")
    return observed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect", help="write one immutable component receipt")
    collect_parser.add_argument("--work", type=Path, required=True)
    validate_parser = commands.add_parser("validate", help="reconstruct one retained component receipt")
    validate_parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "collect":
            print(execute(ROOT, args.work))
        else:
            validate_receipt(ROOT, args.receipt)
            print("installed loader component receipt valid; family and platform gates remain independent")
    except (LoaderFamilyError, OSError, ValueError) as error:
        parser.exit(1, f"owned loader family: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
