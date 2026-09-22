#!/usr/bin/env python3
"""Assess the fixed, non-promoting native x86 resolver-family evidence.

The coordinator consumes only explicitly named retained component reports.  It
does not build products, run DNS fixtures, discover report directories, or turn
a component pass into `libc.resolver` completion.  Its useful result today is a
source-checked capability-to-proof map and an explicit failure for behavior
that has no public retained reader.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import stat
import tomllib
from typing import Any, Callable, Mapping


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-resolver-family/v1"
REQUEST_SCHEMA = "crabc.x86_64-owned-resolver-family-request/v1"
ROSTER_SCHEMA = "crabc.x86_64-owned-resolver-family-roster/v1"
FROZEN_CAPABILITIES = (
    "network.resolver-transport",
    "network.resolver",
    "network.netdb",
)
SIX_MODES = (
    "static-et-exec",
    "static-pie",
    "dynamic-pie-kernel",
    "dynamic-pie-direct",
    "dynamic-non-pie-kernel",
    "dynamic-non-pie-direct",
)
EXPECTED_COMPONENTS = {
    "resolver-network-physical": (
        "reader", "compat/x86_64/resolver_network_component_receipt.py", None, ("report",),
        ("installed", "extracted"), SIX_MODES,
    ),
    "classic-netdb": (
        "reader", "compat/x86_64/owned_classic_netdb_component_receipt.py", None, ("report",),
        ("supplied-static-and-dynamic-pair",), SIX_MODES,
    ),
    "resolver-alias-private-bodies": (
        "reader", "compat/x86_64/owned_resolver_alias_contract_reader.py", None,
        ("report", "static_product", "dynamic_product", "product_report", "static_preparation", "elf_facts", "base_inventory"),
        ("one-current-static-and-dynamic-cohort",),
        ("static-et-exec", "static-pie", "dynamic-pie-kernel", "dynamic-non-pie-kernel"),
    ),
    "resolver-cancellation": (
        "reader", "compat/x86_64/owned_resolver_cancellation_receipt.py", None,
        ("work", "static_product", "dynamic_product"),
        ("one-supplied-static-and-dynamic-pair",), SIX_MODES,
    ),
    "protocol-database-product": (
        "reader", "compat/x86_64/owned_protocol_database_receipt.py", None, ("report",),
        ("installed", "reproduction", "extracted"), SIX_MODES,
    ),
    "resolver-family-cohort": (
        "reader", "compat/x86_64/owned_resolver_family_cohort.py", None,
        ("static_preparation", "dynamic_qualification"),
        ("primary", "reproduction", "extracted"), SIX_MODES,
    ),
}
EXPECTED_PROOFS = {
    "transport-controlled-network": (
        "resolver-network-physical", ("network.resolver-transport", "network.resolver"),
    ),
    "netdb-classic-and-modern": (
        "classic-netdb", ("network.resolver", "network.netdb")),
    "resolver-public-state-and-aliases": (
        "resolver-alias-private-bodies", ("network.resolver",)),
    "resolver-cancellation-and-retirement": (
        "resolver-cancellation", ("network.resolver-transport", "network.resolver")),
    "protocol-database-installed-behavior": (
        "protocol-database-product", ("network.netdb",)),
    "common-current-product-cohort": (
        "resolver-family-cohort", FROZEN_CAPABILITIES),
}


class ResolverFamilyError(RuntimeError):
    """A required resolver-family input is absent, mutable, or malformed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ResolverFamilyError(message)


def _pairs(values: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in values:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ResolverFamilyError(f"cannot read {description}: {error}") from error
    require(isinstance(value, dict), f"{description} must be a JSON object")
    return value


def _physical(path: Path, description: str, *, directory: bool = False) -> Path:
    """Accept only an existing regular path with no symlinked component."""

    try:
        result = Path(os.path.abspath(path))
        metadata = result.lstat()
        require(not result.is_symlink(), f"{description} is a symlink: {path}")
        require(stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode),
                f"{description} has the wrong type: {path}")
        current = Path(result.anchor)
        for part in result.parts[1:]:
            current /= part
            require(not current.is_symlink(), f"{description} traverses a symlink: {path}")
        return result
    except OSError as error:
        raise ResolverFamilyError(f"cannot read {description}: {path}") from error


def _relative_path(root: Path, value: object, description: str, *, below_work: bool = False,
                   directory: bool = False) -> Path:
    require(isinstance(value, str) and value, f"{description} path is absent")
    relative = Path(value)
    require(not relative.is_absolute() and relative.parts and
            all(part not in {"", ".", ".."} for part in relative.parts),
            f"{description} path escapes the checkout")
    path = _physical(root / relative, description, directory=directory)
    require(path.is_relative_to(root), f"{description} path escapes the checkout")
    if below_work:
        require(path.is_relative_to(root / ".work"), f"{description} must be below checkout .work")
    return path


def _relative_file(root: Path, value: object, description: str, *, below_work: bool = False) -> Path:
    return _relative_path(root, value, description, below_work=below_work)


def _request_file(root: Path, value: Path, description: str) -> Path:
    """Accept a public API path only after reducing it to a checkout-relative path."""

    if value.is_absolute():
        try:
            value = value.relative_to(root)
        except ValueError as error:
            raise ResolverFamilyError(f"{description} path escapes the checkout") from error
    return _relative_file(root, value.as_posix(), description, below_work=True)


def _identity(root: Path, path: Path) -> dict[str, object]:
    path = _physical(path, "identity input")
    require(path.is_relative_to(root), f"identity input escapes checkout: {path}")
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(path.read_bytes()).hexdigest(),
        "byte_length": path.stat().st_size,
        "mode": stat.S_IMODE(path.stat().st_mode),
    }


def _input_identity(root: Path, path: Path) -> dict[str, object]:
    """Hash one declared file or product tree without scanning unrelated `.work`."""

    path = Path(path)
    if path.is_file():
        return _identity(root, path)
    path = _physical(path, "directory identity input", directory=True)
    require(path.is_relative_to(root), f"directory identity input escapes checkout: {path}")
    digest = sha256()
    entries = 0

    def append(kind: str, relative: Path, metadata: os.stat_result, value: bytes = b"") -> None:
        nonlocal entries
        entries += 1
        digest.update(kind.encode("ascii") + b"\0")
        digest.update(relative.as_posix().encode("utf-8") + b"\0")
        digest.update(f"{stat.S_IMODE(metadata.st_mode):o}".encode("ascii") + b"\0")
        digest.update(value)
        digest.update(b"\0")

    def visit(directory: Path, relative: Path) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise ResolverFamilyError(f"cannot read product identity directory: {directory}") from error
        for entry in children:
            child = directory / entry.name
            child_relative = relative / entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise ResolverFamilyError(f"cannot stat product identity entry: {child}") from error
            if stat.S_ISLNK(metadata.st_mode):
                try:
                    append("link", child_relative, metadata, os.readlink(child).encode("utf-8"))
                except OSError as error:
                    raise ResolverFamilyError(f"cannot read product identity link: {child}") from error
            elif stat.S_ISDIR(metadata.st_mode):
                append("directory", child_relative, metadata)
                visit(child, child_relative)
            elif stat.S_ISREG(metadata.st_mode):
                try:
                    append("file", child_relative, metadata, sha256(child.read_bytes()).digest())
                except OSError as error:
                    raise ResolverFamilyError(f"cannot hash product identity file: {child}") from error
            else:
                raise ResolverFamilyError(f"product identity contains unsupported entry: {child}")

    append("directory", Path("."), path.stat())
    visit(path, Path("."))
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": digest.hexdigest(),
        "entries": entries,
        "mode": stat.S_IMODE(path.stat().st_mode),
    }


@dataclass(frozen=True)
class Component:
    identifier: str
    state: str
    reader: str | None
    required_reader: str | None
    request_fields: tuple[str, ...]
    products: tuple[str, ...]
    modes: tuple[str, ...]
    role: str


@dataclass(frozen=True)
class Proof:
    identifier: str
    component: str
    capabilities: tuple[str, ...]
    behaviors: tuple[str, ...]


def _string_tuple(value: object, description: str) -> tuple[str, ...]:
    require(isinstance(value, list) and all(isinstance(item, str) and item for item in value),
            f"{description} must be a non-empty string list")
    result = tuple(value)
    require(len(result) == len(set(result)), f"{description} is duplicated")
    return result


def _roster(root: Path) -> tuple[dict[str, Component], tuple[Proof, ...]]:
    path = _physical(root / "compat/x86_64/resolver-family.toml", "resolver family roster")
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ResolverFamilyError(f"cannot parse resolver family roster: {error}") from error
    require(raw.get("schema") == ROSTER_SCHEMA and raw.get("family") == "libc.resolver",
            "resolver family roster identity differs")
    require(raw.get("baseline_capability_ledger") == "compat/crabc-rs/coverage.toml" and
            raw.get("frozen_baseline") == "compat/x86_64/aarch64_frozen_baseline.json",
            "resolver family roster baseline paths differ")
    require(_string_tuple(raw.get("frozen_capabilities"), "frozen resolver capabilities") == FROZEN_CAPABILITIES,
            "resolver family frozen capability roster differs")
    require(_string_tuple(raw.get("six_modes"), "resolver family six-mode roster") == SIX_MODES,
            "resolver family six-mode roster differs")

    component_rows = raw.get("component")
    require(isinstance(component_rows, list), "resolver family component roster is absent")
    components: dict[str, Component] = {}
    for row in component_rows:
        require(isinstance(row, dict), "resolver family component is malformed")
        identifier = row.get("id")
        require(isinstance(identifier, str) and identifier and identifier not in components,
                "resolver family component identifier differs")
        state = row.get("state")
        require(state in {"reader", "missing-reader"}, f"resolver component {identifier} state differs")
        reader = row.get("reader")
        required_reader = row.get("required_reader")
        if state == "reader":
            require(isinstance(reader, str) and reader.startswith("compat/x86_64/") and
                    isinstance(row.get("request_fields"), list),
                    f"resolver component {identifier} reader contract differs")
            require(required_reader is None, f"resolver component {identifier} has both reader forms")
        else:
            require(reader is None and isinstance(required_reader, str) and required_reader,
                    f"resolver component {identifier} missing-reader contract differs")
            require("request_fields" not in row, f"resolver component {identifier} cannot accept a receipt")
        components[identifier] = Component(
            identifier, state, reader if isinstance(reader, str) else None,
            required_reader if isinstance(required_reader, str) else None,
            _string_tuple(row.get("request_fields", []), f"resolver component {identifier} request fields")
            if state == "reader" else (),
            _string_tuple(row.get("products"), f"resolver component {identifier} products"),
            _string_tuple(row.get("modes"), f"resolver component {identifier} modes"),
            row.get("role") if isinstance(row.get("role"), str) and row["role"] else "",
        )
        require(components[identifier].role, f"resolver component {identifier} role is absent")
    require(set(components) == set(EXPECTED_COMPONENTS), "resolver family component roster differs")
    for identifier, expected in EXPECTED_COMPONENTS.items():
        component = components[identifier]
        require(
            (component.state, component.reader, component.required_reader, component.request_fields,
             component.products, component.modes) == expected,
            f"resolver component {identifier} contract differs",
        )

    proof_rows = raw.get("proof")
    require(isinstance(proof_rows, list), "resolver family proof roster is absent")
    proofs: list[Proof] = []
    for row in proof_rows:
        require(isinstance(row, dict), "resolver family proof is malformed")
        identifier, component = row.get("id"), row.get("component")
        require(isinstance(identifier, str) and identifier and isinstance(component, str) and component in components,
                "resolver family proof identity differs")
        proofs.append(Proof(identifier, component,
                            _string_tuple(row.get("capabilities"), f"resolver proof {identifier} capabilities"),
                            _string_tuple(row.get("behaviors"), f"resolver proof {identifier} behaviors")))
    require({proof.identifier for proof in proofs} == set(EXPECTED_PROOFS) and
            len(proofs) == len(EXPECTED_PROOFS), "resolver family proof roster differs")
    for proof in proofs:
        expected_component, expected_capabilities = EXPECTED_PROOFS[proof.identifier]
        require((proof.component, proof.capabilities) == (expected_component, expected_capabilities),
                f"resolver proof {proof.identifier} contract differs")
    for capability in FROZEN_CAPABILITIES:
        require(any(capability in proof.capabilities for proof in proofs),
                f"resolver capability {capability} has no required behavior proof")
    return components, tuple(proofs)


def _frozen_capability_projection(root: Path) -> dict[str, dict[str, object]]:
    baseline_path = _physical(root / "compat/x86_64/aarch64_frozen_baseline.json", "frozen AArch64 baseline")
    baseline = _read_json(baseline_path, "frozen AArch64 baseline")
    inputs = baseline.get("aarch64_inputs")
    require(isinstance(inputs, dict) and isinstance(inputs.get("capability_ledger"), dict),
            "frozen AArch64 capability input is absent")
    ledger_record = inputs["capability_ledger"]
    ledger_path = _physical(root / "compat/crabc-rs/coverage.toml", "frozen capability ledger")
    require(ledger_record.get("path") == "compat/crabc-rs/coverage.toml" and
            ledger_record.get("sha256") == sha256(ledger_path.read_bytes()).hexdigest(),
            "frozen capability ledger has drifted")
    try:
        with ledger_path.open("rb") as stream:
            ledger = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ResolverFamilyError(f"cannot parse frozen capability ledger: {error}") from error
    rows = ledger.get("capability")
    require(isinstance(rows, list), "frozen capability ledger has no rows")
    found: dict[str, dict[str, object]] = {}
    for row in rows:
        if isinstance(row, dict) and row.get("id") in FROZEN_CAPABILITIES:
            identifier = row["id"]
            require(identifier not in found, f"frozen resolver capability {identifier} is duplicated")
            require(row.get("status") == "verified", f"frozen resolver capability {identifier} is not verified")
            found[identifier] = {
                "kind": row.get("kind"),
                "classification": row.get("classification"),
                "symbols": row.get("symbols", []),
                "evidence": row.get("evidence", []),
            }
    require(tuple(found) == FROZEN_CAPABILITIES, "frozen resolver capability set differs")
    return found


def _reader_path(root: Path, component: Component) -> Path:
    assert component.reader is not None
    path = _physical(root / component.reader, f"resolver component {component.identifier} reader")
    require(path.is_relative_to(root), f"resolver component {component.identifier} reader escapes checkout")
    return path


def _network_reader(root: Path, paths: Mapping[str, Path]) -> dict[str, object]:
    module = importlib.import_module("resolver_network_component_receipt")
    report = module.validate_report(root, paths["report"])
    labels = tuple(module.expected_candidate_labels())
    require(labels == tuple(
        f"{arm}-{mode}" for arm in ("installed", "extracted") for mode in (
            "static-et-exec", "static-pie", "dynamic-pie-ordinary", "dynamic-pie-direct-entry",
            "dynamic-non-pie-ordinary", "dynamic-non-pie-direct-entry",
        )
    ), "resolver-network reader candidate mode roster differs")
    return {"reader_schema": module.RECEIPT_SCHEMA, "report": report,
            "candidate_labels": list(labels)}


def _classic_reader(root: Path, paths: Mapping[str, Path]) -> dict[str, object]:
    module = importlib.import_module("owned_classic_netdb_component_receipt")
    report = module.validate_report(root, paths["report"], require_static=True)
    require(tuple(module.FULL_CELLS) == (
        "static", "static-pie", "dynamic-pie-kernel", "dynamic-pie-direct",
        "dynamic-non-pie-kernel", "dynamic-non-pie-direct",
    ), "classic-netdb reader six-mode roster differs")
    return {"reader_schema": module.SCHEMA, "report": report,
            "behavior_roster": module.BEHAVIOR_ROSTER, "cells": list(module.FULL_CELLS)}


def _alias_reader(root: Path, paths: Mapping[str, Path]) -> dict[str, object]:
    module = importlib.import_module("owned_resolver_alias_contract_reader")
    report = module.validate_report(
        paths["report"], root=root, static_product=paths["static_product"],
        dynamic_product=paths["dynamic_product"], product_report=paths["product_report"],
        static_preparation=paths["static_preparation"], elf_facts=paths["elf_facts"],
        base_inventory=paths["base_inventory"],
    )
    require(tuple(module.ALIASES) == (
        ("res_mkquery", "__res_mkquery"), ("res_send", "__res_send"), ("res_search", "res_query"),
    ), "resolver alias reader route roster differs")
    return {"reader_schema": module.SCHEMA, "report": report,
            "aliases": [list(alias) for alias in module.ALIASES]}


def _cancellation_reader(root: Path, paths: Mapping[str, Path]) -> dict[str, object]:
    module = importlib.import_module("owned_resolver_cancellation_receipt")
    report = module.validate_report(
        root, paths["work"], static_product=paths["static_product"],
        dynamic_product=paths["dynamic_product"], require_static=True,
    )
    require(tuple(module.ENTRY_MODES) == SIX_MODES,
            "resolver cancellation reader six-mode roster differs")
    return {
        "reader_schema": module.SCHEMA,
        "report": report,
        "entry_modes": list(module.ENTRY_MODES),
        "case_count": len(importlib.import_module("owned_resolver_cancellation").CASES),
    }


def _protocol_database_reader(root: Path, paths: Mapping[str, Path]) -> dict[str, object]:
    module = importlib.import_module("owned_protocol_database_receipt")
    report = module.validate_report(root, paths["report"])
    require(tuple(module.ENTRY_MODES) == SIX_MODES,
            "protocol-database reader six-mode roster differs")
    require(tuple(module.ARMS) == ("installed", "reproduction", "extracted"),
            "protocol-database reader product-arm roster differs")
    return {
        "reader_schema": module.SCHEMA,
        "report": report,
        "entry_modes": list(module.ENTRY_MODES),
        "product_arms": list(module.ARMS),
        "provider_symbols": list(module.PROVIDERS),
    }


def _cohort_product_path(root: Path, path: Path, description: str) -> str:
    """Return one reader-validated product root in assessment-safe form."""

    path = _physical(path, description, directory=True)
    require(path.is_relative_to(root / ".work"), f"{description} escapes checkout .work")
    return path.relative_to(root).as_posix()


def _resolver_family_component_products(
    root: Path, replays: Mapping[str, tuple[Mapping[str, Path], Mapping[str, object]]],
) -> dict[str, object]:
    """Recover only roots already validated by the five behavior readers.

    The cohort reader does not reinterpret retained behavior output.  It gets
    the exact product roots that each component reader just accepted, then
    binds them to one current static/dynamic product preparation.
    """

    expected = {
        "resolver-network-physical", "classic-netdb", "resolver-alias-private-bodies",
        "resolver-cancellation", "protocol-database-product",
    }
    require(set(replays) == expected, "resolver cohort requires every behavior component replay")

    network_paths, network_result = replays["resolver-network-physical"]
    network_report = network_result.get("report")
    require(isinstance(network_report, dict), "resolver-network reader has no accepted report")
    network_module = importlib.import_module("resolver_network_component_receipt")
    network_products = network_module.product_paths(root, network_report)
    network = {
        "primary": {
            kind: _cohort_product_path(root, network_products["installed"][kind],
                                       f"resolver-network installed {kind} product")
            for kind in ("static", "dynamic")
        },
        "extracted": {
            kind: _cohort_product_path(root, network_products["extracted"][kind],
                                       f"resolver-network extracted {kind} product")
            for kind in ("static", "dynamic")
        },
    }
    require(network_paths["report"].is_file(), "resolver-network report changed after replay")

    classic_paths, classic_result = replays["classic-netdb"]
    classic_report = classic_result.get("report")
    require(isinstance(classic_report, dict), "classic-netdb reader has no accepted report")
    classic_module = importlib.import_module("owned_classic_netdb_component_receipt")
    classic_values = classic_report.get("products")
    require(isinstance(classic_values, dict) and set(classic_values) == {"static", "dynamic"},
            "classic-netdb accepted report lacks the static/dynamic pair")
    classic = {"selected": {
        kind: _cohort_product_path(
            root,
            classic_module.checkout_directory(root, classic_values[kind], f"classic-netdb {kind} product"),
            f"classic-netdb {kind} product",
        )
        for kind in ("static", "dynamic")
    }}
    require(classic_paths["report"].is_file(), "classic-netdb report changed after replay")

    alias_paths, _alias_result = replays["resolver-alias-private-bodies"]
    alias = {"selected": {
        kind: _cohort_product_path(root, alias_paths[f"{kind}_product"], f"resolver alias {kind} product")
        for kind in ("static", "dynamic")
    }}

    cancellation_paths, _cancellation_result = replays["resolver-cancellation"]
    cancellation = {"selected": {
        kind: _cohort_product_path(root, cancellation_paths[f"{kind}_product"],
                                   f"resolver cancellation {kind} product")
        for kind in ("static", "dynamic")
    }}

    protocol_paths, _protocol_result = replays["protocol-database-product"]
    protocol_report = _read_json(protocol_paths["report"], "protocol-database accepted report")
    protocol_products = protocol_report.get("products")
    require(isinstance(protocol_products, dict) and set(protocol_products) == {"before", "after"}
            and protocol_products["before"] == protocol_products["after"],
            "protocol-database accepted report product seal differs")
    protocol_before = protocol_products["before"]
    require(isinstance(protocol_before, dict) and set(protocol_before) == {"installed", "reproduction", "extracted"},
            "protocol-database accepted report product arms differ")
    protocol: dict[str, object] = {}
    for source_arm, cohort_arm in (("installed", "primary"), ("reproduction", "reproduction"),
                                   ("extracted", "extracted")):
        arm = protocol_before[source_arm]
        require(isinstance(arm, dict) and set(arm) == {"static", "dynamic"},
                f"protocol-database {source_arm} product kind roster differs")
        products: dict[str, str] = {}
        for kind in ("static", "dynamic"):
            record = arm[kind]
            require(isinstance(record, dict) and isinstance(record.get("path"), str),
                    f"protocol-database {source_arm} {kind} path differs")
            path = _relative_path(root, record["path"], f"protocol-database {source_arm} {kind} product",
                                  directory=True)
            expected_manifest = _identity(root, path / "share/crabc/manifest.json")
            require(record.get("manifest") == expected_manifest,
                    f"protocol-database {source_arm} {kind} manifest identity differs")
            products[kind] = _cohort_product_path(root, path, f"protocol-database {source_arm} {kind} product")
        protocol[cohort_arm] = products

    return {
        "resolver-network-physical": network,
        "classic-netdb": classic,
        "resolver-alias-private-bodies": alias,
        "resolver-cancellation": cancellation,
        "protocol-database-product": protocol,
    }


def _resolver_family_cohort_reader(
    root: Path, paths: Mapping[str, Path], replays: Mapping[str, tuple[Mapping[str, Path], Mapping[str, object]]],
) -> dict[str, object]:
    module = importlib.import_module("owned_resolver_family_cohort")
    report = module.validate(
        root,
        static_preparation=paths["static_preparation"],
        dynamic_qualification=paths["dynamic_qualification"],
        component_products=_resolver_family_component_products(root, replays),
    )
    require(report.get("schema") == module.SCHEMA and report.get("family_completion") is False
            and report.get("promotion_ready") is False and report.get("public_support") is False,
            "resolver cohort reader result differs")
    return report


Reader = Callable[[Path, Mapping[str, Path]], dict[str, object]]
READERS: dict[str, Reader] = {
    "resolver-network-physical": _network_reader,
    "classic-netdb": _classic_reader,
    "resolver-alias-private-bodies": _alias_reader,
    "resolver-cancellation": _cancellation_reader,
    "protocol-database-product": _protocol_database_reader,
}
CohortReader = Callable[[Path, Mapping[str, Path], Mapping[str, tuple[Mapping[str, Path], Mapping[str, object]]]],
                        dict[str, object]]
DIRECTORY_INPUTS = {
    "resolver-alias-private-bodies": frozenset(("static_product", "dynamic_product")),
    "resolver-cancellation": frozenset(("work", "static_product", "dynamic_product")),
}


def _request(root: Path, request_path: Path) -> tuple[Path, dict[str, object]]:
    request = _request_file(root, request_path, "resolver family request")
    value = _read_json(request, "resolver family request")
    require(set(value) == {"schema", "components"} and value["schema"] == REQUEST_SCHEMA,
            "resolver family request schema differs")
    require(isinstance(value["components"], dict), "resolver family request components differ")
    return request, value


def _component_paths(root: Path, component: Component, value: object) -> dict[str, Path]:
    require(isinstance(value, dict) and set(value) == set(component.request_fields),
            f"resolver component {component.identifier} request fields differ")
    directories = DIRECTORY_INPUTS.get(component.identifier, frozenset())
    return {name: _relative_path(root, value[name], f"resolver component {component.identifier} {name}",
                                 directory=name in directories)
            for name in component.request_fields}


def collect(root: Path, request_path: Path, *, readers: Mapping[str, Reader] | None = None,
            cohort_reader: CohortReader | None = None) -> dict[str, object]:
    """Reconstruct named component receipts and return an explicit family assessment."""

    root = _physical(root, "checkout root", directory=True)
    require((root / ".work").is_dir(), "checkout root has no .work directory")
    components, proofs = _roster(root)
    frozen = _frozen_capability_projection(root)
    request, request_value = _request(root, request_path)
    declared = request_value["components"]
    assert isinstance(declared, dict)
    require(set(declared).issubset(set(components)), "resolver family request names an unknown component")
    reader_map = READERS if readers is None else readers
    selected_cohort_reader = _resolver_family_cohort_reader if cohort_reader is None else cohort_reader
    component_results: dict[str, object] = {}
    gaps: list[dict[str, object]] = []
    successful_replays: dict[str, tuple[Mapping[str, Path], Mapping[str, object]]] = {}
    for identifier, component in components.items():
        _reader_path(root, component)
        if identifier not in declared:
            gap = {"component": identifier, "reason": "missing-component-report",
                   "required_fields": list(component.request_fields)}
            component_results[identifier] = {
                "state": component.state,
                "role": component.role,
                "products": list(component.products),
                "modes": list(component.modes),
                "admitted": False,
                "gap": gap,
            }
            gaps.append(gap)
            continue
        try:
            paths = _component_paths(root, component, declared[identifier])
            before = {name: _input_identity(root, path) for name, path in paths.items()}
            result = (selected_cohort_reader(root, paths, successful_replays)
                      if identifier == "resolver-family-cohort" else reader_map[identifier](root, paths))
            require(before == {name: _input_identity(root, path) for name, path in paths.items()},
                    f"resolver component {identifier} input changed during reader replay")
        except (ResolverFamilyError, OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
            gap = {"component": identifier, "reason": "component-reader-rejected", "detail": str(error)}
            component_results[identifier] = {
                "state": component.state,
                "role": component.role,
                "products": list(component.products),
                "modes": list(component.modes),
                "admitted": False,
                "gap": gap,
            }
            gaps.append(gap)
            continue
        if identifier != "resolver-family-cohort":
            require(isinstance(result, dict), f"resolver component {identifier} reader result differs")
            successful_replays[identifier] = (paths, result)
        component_results[identifier] = {
            "state": component.state,
            "role": component.role,
            "products": list(component.products),
            "modes": list(component.modes),
            "admitted": True,
            "reader": component.reader,
            "inputs": before,
            "result": result,
        }

    proof_results: dict[str, object] = {}
    capability_proofs: dict[str, list[str]] = {identifier: [] for identifier in FROZEN_CAPABILITIES}
    for proof in proofs:
        component = component_results[proof.component]
        assert isinstance(component, dict)
        admitted = component["admitted"] is True
        proof_results[proof.identifier] = {
            "component": proof.component,
            "capabilities": list(proof.capabilities),
            "behaviors": list(proof.behaviors),
            "admitted": admitted,
        }
        for capability in proof.capabilities:
            capability_proofs[capability].append(proof.identifier)
    capability_results = {
        identifier: {
            "frozen": frozen[identifier],
            "required_proofs": capability_proofs[identifier],
            "admitted": all(proof_results[proof]["admitted"] for proof in capability_proofs[identifier]),
        }
        for identifier in FROZEN_CAPABILITIES
    }
    complete = not gaps and all(value["admitted"] for value in capability_results.values())
    return {
        "schema": SCHEMA,
        "family": "libc.resolver",
        "contract": _identity(root, root / "compat/x86_64/resolver-family.toml"),
        "request": _identity(root, request),
        "capabilities": capability_results,
        "components": component_results,
        "proofs": proof_results,
        "gaps": gaps,
        "family_complete": complete,
        "promotion_ready": False,
        "public_support": False,
    }


def write_assessment(root: Path, request_path: Path, output_path: Path) -> Path:
    """Write one immutable, possibly incomplete assessment below checkout `.work`."""

    root = _physical(root, "checkout root", directory=True)
    output = root / output_path
    require(not output_path.is_absolute() and output.is_relative_to(root / ".work"),
            "resolver family assessment output must be below checkout .work")
    require(not output.exists(), "resolver family assessment output already exists")
    parent = _physical(output.parent, "resolver family assessment parent", directory=True)
    require(parent.is_relative_to(root / ".work"), "resolver family assessment parent escapes .work")
    assessment = collect(root, request_path)
    try:
        with output.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(assessment, indent=2, sort_keys=True, allow_nan=False) + "\n")
        output.chmod(0o444)
    except OSError as error:
        raise ResolverFamilyError(f"cannot write resolver family assessment: {error}") from error
    return output


def validate_assessment(root: Path, assessment_path: Path) -> dict[str, object]:
    root = _physical(root, "checkout root", directory=True)
    assessment = _request_file(root, assessment_path, "resolver family assessment")
    retained = _read_json(assessment, "resolver family assessment")
    require(retained.get("schema") == SCHEMA, "resolver family assessment schema differs")
    request_record = retained.get("request")
    require(isinstance(request_record, dict) and set(request_record) == {"path", "sha256", "byte_length", "mode"},
            "resolver family assessment request identity differs")
    request = _relative_file(root, request_record["path"], "resolver family assessment request", below_work=True)
    require(_identity(root, request) == request_record, "resolver family assessment request changed")
    reconstructed = collect(root, request.relative_to(root))
    require(retained == reconstructed, "resolver family assessment does not reconstruct")
    return reconstructed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    assess = commands.add_parser("assess", help="reconstruct explicit component inputs without native execution")
    assess.add_argument("--request", type=Path, required=True)
    write = commands.add_parser("write-assessment", help="write one immutable non-promoting assessment")
    write.add_argument("--request", type=Path, required=True)
    write.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate", help="reconstruct an assessment and require full evidence")
    validate.add_argument("--assessment", type=Path, required=True)
    values = parser.parse_args()
    try:
        if values.command == "assess":
            print(json.dumps(collect(ROOT, values.request), sort_keys=True))
            return 0
        if values.command == "write-assessment":
            print(write_assessment(ROOT, values.request, values.output))
            return 0
        assessment = validate_assessment(ROOT, values.assessment)
        require(assessment["family_complete"] is True,
                "resolver family remains incomplete; see retained gaps")
        print("resolver family evidence is complete; promotion remains independent")
    except ResolverFamilyError as error:
        parser.exit(1, f"owned resolver family: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
