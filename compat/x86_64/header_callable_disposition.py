#!/usr/bin/env python3
"""Generate checked x86 ownership routing for public header callables.

The compiler-derived header inventory establishes which selected external
function names exist. Its current provider partition establishes the current
selected default-static and verified-feature provider assignments. This report
is a derived routing projection: it adds the missing exact semantic
deferred-owner record for every remaining name, plus a separate exact roster
for declarations which pinned musl exposes but the project headers still omit.

This is deliberately not archive-extraction or runtime evidence.  A deferred
owner makes a remaining obligation findable; it never asserts that a C ABI
provider exists or that the selected archive can extract one.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from header_callable_linkage_audit import (  # noqa: E402
    callable_provider_partition,
    candidate_external_symbols,
    load_json as load_inventory_json,
    load_static_exports,
    sha256_file,
)


CONTRACT_PATH = ROOT / "compat" / "x86_64" / "header_callable_disposition.toml"
SCHEMA = "crabc.x86_64-header-callable-disposition-report/v1"
CONTRACT_SCHEMA = "crabc.x86_64-header-callable-disposition/v1"
TARGET = "x86_64-unknown-linux-musl"
PLATFORM = "Linux/x86-64 little-endian"
ORACLE = "Pinned musl 1.2.6"
SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DEFERRED_RESOLUTIONS = {
    "planned-provider",
    "compiler-builtin",
    "consumer-supplied",
    "oracle-declared-no-provider",
    "policy-decision-required",
}
MISSING_REFERENCE_RESOLUTION = "candidate-declaration-missing"


class HeaderCallableDispositionError(ValueError):
    """The checked callable-disposition input is not a finite safe contract."""


@dataclass(frozen=True)
class DeferredOwnerGroup:
    identifier: str
    semantic_family: str
    linkage_owner_family: str
    linkage_owner_obligation: str
    resolution: str
    provider_target: str
    source_oracle: str
    members: tuple[str, ...]

    def as_report(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "linkage_owner_family": self.linkage_owner_family,
            "linkage_owner_obligation": self.linkage_owner_obligation,
            "members": list(self.members),
            "provider_target": self.provider_target,
            "resolution": self.resolution,
            "semantic_family": self.semantic_family,
            "source_oracle": self.source_oracle,
        }


@dataclass(frozen=True)
class MissingReferenceDeclarationGroup:
    identifier: str
    semantic_family: str
    resolution: str
    source_oracle: str
    members: tuple[str, ...]

    def as_report(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "members": list(self.members),
            "resolution": self.resolution,
            "semantic_family": self.semantic_family,
            "source_oracle": self.source_oracle,
        }


@dataclass(frozen=True)
class DispositionContract:
    callable_inventory: Path
    static_exports: Path
    parity_ledger: Path
    generated_report: Path
    policy: dict[str, bool]
    work_package: dict[str, Any]
    deferred_owner_groups: tuple[DeferredOwnerGroup, ...]
    missing_reference_declaration_groups: tuple[MissingReferenceDeclarationGroup, ...]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HeaderCallableDispositionError(message)


def safe_project_file(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty repository path")
    relative = Path(value)
    require(not relative.is_absolute() and ".." not in relative.parts, f"{location} escapes the repository")
    path = ROOT / relative
    require(path.is_file() and not path.is_symlink(), f"{location} is not a safe repository file: {value}")
    return path


def safe_project_destination(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty repository path")
    relative = Path(value)
    require(not relative.is_absolute() and ".." not in relative.parts, f"{location} escapes the repository")
    path = ROOT / relative
    require(path.parent.is_dir() and not path.parent.is_symlink(), f"{location} parent is unsafe")
    require(not path.is_symlink(), f"{location} is a symlink")
    return path


def string_list(value: object, location: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    require(isinstance(value, list), f"{location} must be an array")
    members: list[str] = []
    for index, member in enumerate(value):
        require(isinstance(member, str) and member, f"{location}[{index}] is invalid")
        require(SYMBOL_RE.fullmatch(member) is not None, f"{location}[{index}] is not a C identifier")
        members.append(member)
    require(allow_empty or members, f"{location} must not be empty")
    require(members == sorted(members), f"{location} must be ASCII sorted")
    require(len(members) == len(set(members)), f"{location} contains duplicates")
    return tuple(members)


def nonempty_string(value: object, location: str) -> str:
    require(isinstance(value, str) and value, f"{location} must be a nonempty string")
    return value


def family_ids(path: Path) -> set[str]:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise HeaderCallableDispositionError(f"cannot load parity ledger: {error}") from error
    rows = raw.get("family")
    require(isinstance(rows, list), "parity ledger family roster is missing")
    result: set[str] = set()
    for index, row in enumerate(rows):
        require(isinstance(row, Mapping), f"parity ledger family[{index}] is invalid")
        identifier = row.get("id")
        require(isinstance(identifier, str) and identifier, f"parity ledger family[{index}].id is invalid")
        require(identifier not in result, f"parity ledger family {identifier} is duplicated")
        result.add(identifier)
    return result


def work_package(value: object) -> dict[str, Any]:
    require(isinstance(value, Mapping), "work_package must be a table")
    expected = {
        "target_family",
        "target_obligation",
        "blocker",
        "prerequisites",
        "dependent_work",
        "baseline_source",
        "source_owners",
        "focused_evidence_command",
        "family_aggregate_command",
        "negative_scope",
        "expected_transition",
        "evidence",
    }
    require(set(value) == expected, "work_package keys drifted")
    result: dict[str, Any] = {}
    for key in (
        "target_family",
        "target_obligation",
        "blocker",
        "baseline_source",
        "focused_evidence_command",
        "family_aggregate_command",
        "negative_scope",
        "expected_transition",
    ):
        result[key] = nonempty_string(value.get(key), f"work_package.{key}")
    for key in ("prerequisites", "dependent_work", "source_owners", "evidence"):
        raw = value.get(key)
        require(isinstance(raw, list) and raw, f"work_package.{key} must be a nonempty array")
        items: list[str] = []
        for index, item in enumerate(raw):
            items.append(nonempty_string(item, f"work_package.{key}[{index}]"))
        require(len(items) == len(set(items)), f"work_package.{key} contains duplicates")
        result[key] = items
    require(result["target_family"] == "libc.headers-layouts", "work package family drifted")
    require(result["target_obligation"] == "header-callable-disposition", "work package obligation drifted")
    require(
        result["focused_evidence_command"] == "./scripts/dev-x86_64.sh header-callable-disposition",
        "work package focused command drifted",
    )
    return result


def deferred_groups(value: object, known_families: set[str]) -> tuple[DeferredOwnerGroup, ...]:
    require(isinstance(value, list) and value, "deferred_owner_group rows are missing")
    rows: list[DeferredOwnerGroup] = []
    identifiers: set[str] = set()
    expected = {
        "id",
        "semantic_family",
        "linkage_owner_family",
        "linkage_owner_obligation",
        "resolution",
        "provider_target",
        "source_oracle",
        "members",
    }
    for index, raw in enumerate(value):
        location = f"deferred_owner_group[{index}]"
        require(isinstance(raw, Mapping), f"{location} must be a table")
        require(set(raw) == expected, f"{location} keys drifted")
        identifier = nonempty_string(raw.get("id"), f"{location}.id")
        require(identifier not in identifiers, f"deferred owner group {identifier} is duplicated")
        identifiers.add(identifier)
        semantic_family = nonempty_string(raw.get("semantic_family"), f"{location}.semantic_family")
        require(semantic_family in known_families, f"{location}.semantic_family is not a parity family")
        linkage_owner_family = nonempty_string(raw.get("linkage_owner_family"), f"{location}.linkage_owner_family")
        require(linkage_owner_family == "libc.c-abi-compat", f"{location}.linkage_owner_family drifted")
        linkage_owner_obligation = nonempty_string(raw.get("linkage_owner_obligation"), f"{location}.linkage_owner_obligation")
        require(
            linkage_owner_obligation == "final-callable-provider-archive-closure",
            f"{location}.linkage_owner_obligation drifted",
        )
        resolution = raw.get("resolution")
        require(resolution in DEFERRED_RESOLUTIONS, f"{location}.resolution is invalid")
        rows.append(
            DeferredOwnerGroup(
                identifier=identifier,
                semantic_family=semantic_family,
                linkage_owner_family=linkage_owner_family,
                linkage_owner_obligation=linkage_owner_obligation,
                resolution=str(resolution),
                provider_target=nonempty_string(raw.get("provider_target"), f"{location}.provider_target"),
                source_oracle=nonempty_string(raw.get("source_oracle"), f"{location}.source_oracle"),
                members=string_list(raw.get("members"), f"{location}.members"),
            )
        )
    return tuple(rows)


def missing_reference_groups(
    value: object, known_families: set[str]
) -> tuple[MissingReferenceDeclarationGroup, ...]:
    require(isinstance(value, list), "missing_reference_declaration_group rows are invalid")
    rows: list[MissingReferenceDeclarationGroup] = []
    identifiers: set[str] = set()
    expected = {"id", "semantic_family", "resolution", "source_oracle", "members"}
    for index, raw in enumerate(value):
        location = f"missing_reference_declaration_group[{index}]"
        require(isinstance(raw, Mapping), f"{location} must be a table")
        require(set(raw) == expected, f"{location} keys drifted")
        identifier = nonempty_string(raw.get("id"), f"{location}.id")
        require(identifier not in identifiers, f"missing reference group {identifier} is duplicated")
        identifiers.add(identifier)
        semantic_family = nonempty_string(raw.get("semantic_family"), f"{location}.semantic_family")
        require(semantic_family in known_families, f"{location}.semantic_family is not a parity family")
        resolution = raw.get("resolution")
        require(resolution == MISSING_REFERENCE_RESOLUTION, f"{location}.resolution drifted")
        rows.append(
            MissingReferenceDeclarationGroup(
                identifier=identifier,
                semantic_family=semantic_family,
                resolution=str(resolution),
                source_oracle=nonempty_string(raw.get("source_oracle"), f"{location}.source_oracle"),
                members=string_list(raw.get("members"), f"{location}.members"),
            )
        )
    return tuple(rows)


def load_contract(path: Path = CONTRACT_PATH) -> DispositionContract:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise HeaderCallableDispositionError(f"cannot load {path.relative_to(ROOT)}: {error}") from error
    expected = {
        "schema",
        "target",
        "platform",
        "oracle",
        "callable_inventory",
        "static_c_abi_exports",
        "parity_ledger",
        "generated_report",
        "policy",
        "work_package",
        "deferred_owner_group",
        "missing_reference_declaration_group",
    }
    require(set(raw) == expected, "header callable disposition contract keys drifted")
    require(raw.get("schema") == CONTRACT_SCHEMA, "header callable disposition contract schema drifted")
    require(raw.get("target") == TARGET, "header callable disposition contract target drifted")
    require(raw.get("platform") == PLATFORM, "header callable disposition contract platform drifted")
    require(raw.get("oracle") == ORACLE, "header callable disposition contract oracle drifted")
    policy = raw.get("policy")
    expected_policy = {
        "compiler_derived_candidate_externals": True,
        "exclusive_exhaustive_primary_disposition": True,
        "header_ownership_routing": True,
        "archive_extraction": False,
        "runtime_semantics": False,
        "family_promotion": False,
        "public_support": False,
    }
    require(policy == expected_policy, "header callable disposition policy drifted")
    parity_ledger = safe_project_file(raw.get("parity_ledger"), "parity_ledger")
    known_families = family_ids(parity_ledger)
    result = DispositionContract(
        callable_inventory=safe_project_file(raw.get("callable_inventory"), "callable_inventory"),
        static_exports=safe_project_file(raw.get("static_c_abi_exports"), "static_c_abi_exports"),
        parity_ledger=parity_ledger,
        generated_report=safe_project_destination(raw.get("generated_report"), "generated_report"),
        policy=dict(expected_policy),
        work_package=work_package(raw.get("work_package")),
        deferred_owner_groups=deferred_groups(raw.get("deferred_owner_group"), known_families),
        missing_reference_declaration_groups=missing_reference_groups(
            raw.get("missing_reference_declaration_group"), known_families
        ),
    )
    require(
        result.work_package["target_family"] in known_families,
        "work package target family is not in the parity ledger",
    )
    return result


def checked_provider_rows(value: object, location: str) -> list[dict[str, Any]]:
    require(isinstance(value, list), f"{location} must be an array")
    rows: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for index, raw in enumerate(value):
        row_location = f"{location}[{index}]"
        require(isinstance(raw, Mapping), f"{row_location} must be a table")
        identifier = raw.get("id")
        require(isinstance(identifier, str) and identifier and identifier not in identifiers, f"{row_location}.id is invalid")
        identifiers.add(identifier)
        members = string_list(raw.get("members"), f"{row_location}.members", allow_empty=True)
        rows.append({"id": identifier, "members": list(members)})
    # The checked feature roster has an intentionally dependency-oriented
    # profile order. Preserve it rather than inventing a second ordering rule
    # for this ownership projection.
    return rows


def flatten_groups(groups: Sequence[DeferredOwnerGroup | MissingReferenceDeclarationGroup]) -> list[str]:
    members: list[str] = []
    for group in groups:
        members.extend(group.members)
    require(len(members) == len(set(members)), "contract group members overlap")
    return sorted(members)


def missing_reference_records(inventory: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    records = inventory.get("callables")
    require(isinstance(records, list), "inventory callables are missing")
    missing: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, row in enumerate(records):
        require(isinstance(row, Mapping), f"inventory callable[{index}] is invalid")
        if row.get("classification") != "missing" or row.get("reference_classification") != "external":
            continue
        require(row.get("tree") == "comparison", f"missing reference callable[{index}] tree drifted")
        require(row.get("declaration_kind") == "function", f"missing reference callable[{index}] kind drifted")
        name = row.get("name")
        require(isinstance(name, str) and SYMBOL_RE.fullmatch(name) is not None, f"missing reference callable[{index}] name is invalid")
        names.add(name)
        missing.append(dict(row))
    return missing, sorted(names)


def candidate_name_digest(names: Sequence[str]) -> str:
    return hashlib.sha256(("\n".join(names) + "\n").encode("utf-8")).hexdigest()


def build_report(contract: DispositionContract) -> dict[str, Any]:
    try:
        inventory = load_inventory_json(contract.callable_inventory)
        static_exports = load_static_exports(contract.static_exports)
        external = candidate_external_symbols(inventory)
        partition, counts = callable_provider_partition(inventory, external, static_exports)
    except ValueError as error:
        raise HeaderCallableDispositionError(str(error)) from error
    inputs = inventory.get("inputs")
    require(isinstance(inputs, Mapping), "inventory inputs are missing")
    require(
        inputs.get("static_c_abi_exports_sha256") == sha256_file(contract.static_exports),
        "inventory was generated against a different static export ratchet",
    )
    require(
        inputs.get("parity_ledger_sha256") == sha256_file(contract.parity_ledger),
        "inventory was generated against a different parity ledger",
    )
    default_static = partition.get("default_static")
    require(isinstance(default_static, Mapping), "inventory default static provider is invalid")
    default_members = string_list(default_static.get("members"), "inventory default static members", allow_empty=True)
    verified_feature_archives = checked_provider_rows(
        partition.get("verified_feature_archives"), "inventory verified feature providers"
    )
    declared_unverified_feature_archives = checked_provider_rows(
        partition.get("declared_unverified_feature_archives"), "inventory declared-unverified feature providers"
    )
    unprovided = partition.get("unprovided")
    require(isinstance(unprovided, Mapping), "inventory unprovided provider is invalid")
    unprovided_members = string_list(unprovided.get("members"), "inventory unprovided members", allow_empty=True)

    deferred_members = flatten_groups(contract.deferred_owner_groups)
    require(
        deferred_members == list(unprovided_members),
        "deferred owner groups do not exactly cover the inventory unprovided callable partition",
    )
    primary_members = list(default_members)
    for row in (*verified_feature_archives, *declared_unverified_feature_archives):
        primary_members.extend(row["members"])
    primary_members.extend(deferred_members)
    require(len(primary_members) == len(set(primary_members)), "primary callable disposition members overlap")
    undispositioned = sorted(set(external) - set(primary_members))
    unexpected_primary = sorted(set(primary_members) - set(external))
    require(not unexpected_primary, "primary callable disposition includes a noncandidate external name")
    require(not undispositioned, "primary callable disposition leaves candidate external names undispositioned")

    missing_records, missing_names = missing_reference_records(inventory)
    missing_group_members = flatten_groups(contract.missing_reference_declaration_groups)
    require(
        missing_group_members == missing_names,
        "missing reference declaration groups do not exactly cover the inventory missing reference names",
    )
    undispositioned_missing: list[str] = []
    resolution_counts = Counter(
        group.resolution
        for group in contract.deferred_owner_groups
        for _member in group.members
    )
    header_ownership_routing_complete = not undispositioned and not undispositioned_missing
    missing_reference_declaration_routing_complete = not undispositioned_missing
    # Missing reference declarations are only one dimension of header
    # declaration parity. The independent declaration/macro matrix still has
    # red identity rows, so this routing report can never promote that broader
    # completion claim merely because its missing-name roster becomes empty.
    header_declaration_parity_complete = False

    return {
        "schema": SCHEMA,
        "contract_schema": CONTRACT_SCHEMA,
        "target": TARGET,
        "platform": PLATFORM,
        "oracle": ORACLE,
        "inputs": {
            "callable_inventory_sha256": sha256_file(contract.callable_inventory),
            "candidate_external_callable_sha256": candidate_name_digest(external),
            "parity_ledger_sha256": sha256_file(contract.parity_ledger),
            "static_c_abi_exports_sha256": sha256_file(contract.static_exports),
        },
        "scope": dict(contract.policy),
        "work_package": dict(contract.work_package),
        "primary_disposition": {
            "kind": "candidate-external-callable-primary-disposition",
            "declared_unverified_feature_archives": declared_unverified_feature_archives,
            "default_static": {"members": list(default_members)},
            "deferred_owner_groups": [group.as_report() for group in contract.deferred_owner_groups],
            "verified_feature_archives": verified_feature_archives,
        },
        "missing_reference_declaration_groups": [
            group.as_report() for group in contract.missing_reference_declaration_groups
        ],
        "summary": {
            "candidate_external_callable_count": len(external),
            "declared_unverified_feature_callable_count": counts["declared_unverified_feature_archives"],
            "default_static_callable_count": counts["default_static"],
            "deferred_resolution_counts": dict(sorted(resolution_counts.items())),
            "final_provider_archive_closure_complete": False,
            "header_declaration_parity_complete": header_declaration_parity_complete,
            "header_ownership_routing_complete": header_ownership_routing_complete,
            "missing_reference_declaration_name_count": len(missing_names),
            "missing_reference_declaration_record_count": len(missing_records),
            "missing_reference_declaration_routing_complete": missing_reference_declaration_routing_complete,
            "primary_disposition_exact_coverage": not undispositioned and not unexpected_primary,
            "undispositioned_candidate_callable_count": len(undispositioned),
            "undispositioned_missing_reference_name_count": len(undispositioned_missing),
            "unprovided_callable_count": counts["unprovided"],
            "verified_feature_callable_count": counts["verified_feature_archives"],
        },
    }


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def validate_checked_report(report: Mapping[str, Any], contract: DispositionContract) -> None:
    """Reject a stale or altered report without repeating compiler collection."""

    require(isinstance(report, Mapping), "checked callable disposition report must be a table")
    require(
        report == build_report(contract),
        "checked callable disposition report is stale or malformed; regenerate with --write",
    )


def check_output(path: Path, rendered: str) -> None:
    try:
        existing = path.read_text(encoding="utf-8")
    except OSError as error:
        raise HeaderCallableDispositionError(
            f"checked callable disposition report is missing: {path.relative_to(ROOT)} ({error})"
        ) from error
    require(
        existing == rendered,
        f"checked callable disposition report is stale: regenerate {path.relative_to(ROOT)} with --write",
    )


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="update the reviewed checked disposition report")
    parser.add_argument("--check", action="store_true", help="require the checked disposition report to match its inputs")
    parsed = parser.parse_args(arguments)
    require(not (parsed.write and parsed.check), "--write and --check cannot be combined")
    contract = load_contract()
    rendered = canonical_json(build_report(contract))
    if parsed.write:
        contract.generated_report.write_text(rendered, encoding="utf-8")
    elif parsed.check:
        check_output(contract.generated_report, rendered)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HeaderCallableDispositionError as error:
        print(f"ERROR: x86 header callable disposition: {error}", file=sys.stderr)
        raise SystemExit(1)
