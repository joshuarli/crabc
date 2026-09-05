#!/usr/bin/env python3
"""Validate the finite POSIX family proposal without qualifying runtime code.

The frozen capability ledger supplies spelling scope. This catalog additionally
requires complete static/dynamic product matrices and named behavior workloads.
Its descriptive evidence references are review inputs, not execution receipts.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
import tomllib

import aarch64_parity_inventory as parity

ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "compat/x86_64/owned-posix-runtime-catalog.toml"
FAMILY = "libc.posix-runtime"
WORKLOADS = frozenset({
    "legacy-filesystem", "control-residual", "credentials-profile",
    "environment-lifecycle", "signal-full", "kernel-residual",
    "global-state-composition",
})
STATIC_CELLS = tuple(f"{product}:{mode}"
                     for product in ("primary", "reproduction", "extracted")
                     for mode in ("et-exec", "pie"))
DYNAMIC_CELLS = tuple(f"{product}:{mode}:{entry}"
                      for product in ("installed", "second", "extracted")
                      for mode in ("pie", "non-pie")
                      for entry in ("kernel", "direct"))


class CatalogError(ValueError):
    """The proposed family scope or required evidence matrix is incomplete."""


@dataclass(frozen=True)
class Capability:
    symbols: tuple[str, ...]
    source_bindings: tuple[str, ...]
    closure_workloads: tuple[str, ...]


@dataclass(frozen=True)
class PosixCatalog:
    capabilities: Mapping[str, Capability]
    static_cells: tuple[str, ...]
    dynamic_cells: tuple[str, ...]
    # Loading a proposal cannot create a verified/family-complete state.
    status: str = field(default="proposal", init=False)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CatalogError(message)


def strings(value: object, location: str, *, empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{location} must be a list")
    require((empty or bool(value)) and all(isinstance(item, str) and item.strip() for item in value),
            f"{location} must contain nonempty strings")
    require(len(value) == len(set(value)), f"{location} contains duplicates")
    return value


def frozen_family_symbols() -> dict[str, tuple[str, ...]]:
    """Read selected scope only after the existing frozen-input judge passes."""
    parity.validate_frozen_baseline()
    coverage = parity.load_toml(parity.BASELINE_CAPABILITIES_PATH)
    ledger = parity.load_toml(parity.X86_LEDGER_PATH)
    families = [row for row in ledger["family"] if row["id"] == FAMILY]
    require(len(families) == 1, "POSIX family is missing or duplicated")
    selected = strings(families[0]["capabilities"], "POSIX family capability roster")
    capabilities = {row["id"]: tuple(row["symbols"]) for row in coverage["capability"]
                    if row["id"] in selected}
    require(set(selected) <= capabilities.keys(), "POSIX family contains an unknown frozen capability")
    return {identifier: capabilities[identifier] for identifier in selected}


def validate_catalog(document: dict, expected: Mapping[str, tuple[str, ...]],
                     *, root: Path = ROOT) -> PosixCatalog:
    fields = {
        "schema", "status", "family", "frozen_ledger", "frozen_platform", "target",
        "pinned_c_oracle", "capability_count", "symbol_count", "composition",
        "required_product_matrix", "signal_case_audit", "capability", "required_workload",
    }
    require(isinstance(document, dict) and set(document) == fields, "catalog fields differ")
    constants = {
        "schema": "crabc.x86_64-owned-posix-runtime-catalog/v1",
        "status": "proposal", "family": FAMILY,
        "frozen_ledger": "compat/crabc-rs/coverage.toml",
        "frozen_platform": "Linux/AArch64 little-endian",
        "target": "x86_64-unknown-linux-musl", "pinned_c_oracle": "musl 1.2.6",
    }
    require(all(document[key] == value for key, value in constants.items()),
            "catalog is not the selected native POSIX proposal")

    workloads = document["required_workload"]
    require(isinstance(workloads, list) and all(isinstance(row, dict) for row in workloads),
            "workload roster must be a list of tables")
    require(all(set(row) == {"id", "purpose", "product_matrix"} for row in workloads),
            "workload roster fields differ")
    identifiers = strings([row["id"] for row in workloads], "workload roster")
    require(set(identifiers) == WORKLOADS, "required workload roster differs")
    require(all(row["product_matrix"] == "all" and isinstance(row["purpose"], str)
                and row["purpose"].strip() for row in workloads), "workload scope is incomplete")

    rows = document["capability"]
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows),
            "capability roster must be a list of tables")
    capability_fields = {
        "id", "symbols", "source_bindings", "current_installed_evidence",
        "private_or_static_only_evidence", "unproven", "closure_workloads",
    }
    require(all(set(row) == capability_fields for row in rows), "capability roster fields differ")
    identifiers = [row["id"] for row in rows]
    require(all(isinstance(identifier, str) for identifier in identifiers), "invalid capability roster")
    require(len(identifiers) == len(set(identifiers)), "duplicate capability")
    require(set(identifiers) == set(expected), "frozen capability roster differs")
    capabilities = {}
    for row in rows:
        identifier = row["id"]
        require(row["symbols"] == list(expected[identifier]), f"{identifier}: frozen spelling roster differs")
        sources = strings(row["source_bindings"], f"{identifier}: source binding")
        for source in sources:
            path = Path(source)
            require(not path.is_absolute() and ".." not in path.parts,
                    f"{identifier}: source binding escapes checkout")
            target = root / path
            require(target.is_file() and target.resolve() == target,
                    f"{identifier}: source binding is missing or nonphysical: {source}")
        bindings = strings(row["closure_workloads"], f"{identifier}: workload binding")
        require(set(bindings) <= WORKLOADS, f"{identifier}: unknown workload binding")
        for key in ("current_installed_evidence", "private_or_static_only_evidence"):
            strings(row[key], f"{identifier}: {key}", empty=True)
        strings(row["unproven"], f"{identifier}: unproven obligations")
        capabilities[identifier] = Capability(tuple(row["symbols"]), tuple(sources), tuple(bindings))
    require(set().union(*(set(row.closure_workloads) for row in capabilities.values())) == WORKLOADS,
            "workload binding omits a required behavior group")
    require(type(document["capability_count"]) is int and document["capability_count"] == len(expected),
            "capability count differs")
    require(type(document["symbol_count"]) is int
            and document["symbol_count"] == sum(len(value) for value in expected.values()),
            "spelling count differs")

    matrix = document["required_product_matrix"]
    require(isinstance(matrix, dict) and set(matrix) == {"static", "dynamic"}, "product matrix fields differ")
    require(matrix["static"] == list(STATIC_CELLS) and matrix["dynamic"] == list(DYNAMIC_CELLS),
            "required product matrix differs")
    composition = document["composition"]
    prose_fields = {"private_static", "installed_static", "extracted_static", "installed_dynamic", "dynamic_qualification"}
    require(isinstance(composition, dict) and set(composition) == prose_fields | {"dynamic_products"},
            "composition fields differ")
    require(composition["dynamic_products"] == ["installed", "second", "extracted"],
            "composition product labels differ")
    require(all(isinstance(composition[key], str) and composition[key].strip() for key in prose_fields),
            "composition explanation is missing")
    audit = document["signal_case_audit"]
    require(isinstance(audit, dict) and set(audit) == {"scope", "dedicated", "supporting"},
            "signal audit fields differ")
    require(isinstance(audit["scope"], str) and audit["scope"].strip(), "signal audit scope is missing")
    strings(audit["dedicated"], "dedicated signal evidence")
    strings(audit["supporting"], "supporting signal uses")
    return PosixCatalog(MappingProxyType(capabilities), STATIC_CELLS, DYNAMIC_CELLS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args()
    try:
        with CATALOG_PATH.open("rb") as source:
            catalog = validate_catalog(tomllib.load(source), frozen_family_symbols())
        print(f"POSIX family proposal: valid ({len(catalog.capabilities)} capabilities, "
              f"{len(catalog.static_cells)} static and {len(catalog.dynamic_cells)} dynamic cells); "
              "runtime qualification remains open")
    except (CatalogError, parity.InventoryError, OSError, tomllib.TOMLDecodeError) as error:
        parser.exit(1, f"POSIX family catalog: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
