#!/usr/bin/env python3
"""Build and validate the x86-64 view of the AArch64 runtime contract.

This is evidence-accounting infrastructure.  It intentionally derives every
classification from the tracked AArch64 capability ledger, ABI/header oracle,
and the x86 promotion ledger and archive/header ratchets.  It does not infer
runtime support from a symbol count, nor can its report promote x86-64.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = ROOT / "compat" / "x86_64" / "aarch64_parity_inventory.json"
X86_LEDGER_PATH = ROOT / "compat" / "x86_64" / "parity.toml"
BASELINE_CAPABILITIES_PATH = ROOT / "compat" / "crabc-rs" / "coverage.toml"
AARCH64_ABI_MANIFEST_PATH = ROOT / "compat" / "abi" / "musl-1.2.6" / "aarch64" / "manifest.json"
AARCH64_HEADERS_PATH = ROOT / "compat" / "abi" / "musl-1.2.6" / "aarch64" / "headers.tsv"
X86_PUBLIC_HEADERS_PATH = ROOT / "compat" / "x86_64" / "public_headers.txt"
X86_STATIC_EXPORTS_PATH = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"

SCHEMA = "crabc.x86_64-aarch64-parity-inventory/v1"
STATE_IMPLEMENTED = "implemented-foundation"
STATE_SELECTED = "selected-private"
STATE_MISSING = "missing"


class InventoryError(ValueError):
    """The checked-in AArch64-to-x86 inventory is no longer evidence-backed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InventoryError(message)


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InventoryError(f"cannot load {path.relative_to(ROOT)}: {error}") from error
    require(isinstance(value, dict), f"{path.relative_to(ROOT)} must be a TOML table")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sorted_unique_lines(path: Path, *, comments: bool = False) -> list[str]:
    values = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and (not comments or not line.lstrip().startswith("#"))
    ]
    require(values == sorted(values), f"{path.relative_to(ROOT)} must be sorted")
    require(len(values) == len(set(values)), f"{path.relative_to(ROOT)} has duplicate entries")
    return values


def aarch64_public_headers(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    require(lines and lines[0] == "path\tinterface\tbytes\tlines\tsha256", "AArch64 header TSV schema drifted")
    headers: list[str] = []
    for index, line in enumerate(lines[1:], start=2):
        columns = line.split("\t")
        require(len(columns) == 5, f"AArch64 header TSV row {index} has unexpected columns")
        if columns[1] == "public":
            headers.append(columns[0])
    require(headers == sorted(headers), "AArch64 public-header rows must be sorted")
    require(len(headers) == len(set(headers)), "AArch64 public-header rows are duplicated")
    return headers


def family_state(family: Mapping[str, Any]) -> str:
    status = family.get("status")
    if status == "foundation-verified":
        return STATE_IMPLEMENTED
    require(status == "planned", f"family {family.get('id')} has unsupported status {status!r}")
    return STATE_SELECTED if family.get("verified_slice") or family.get("verified_artifact") else STATE_MISSING


def build_inventory() -> dict[str, Any]:
    """Derive a canonical report from the actual ledger and oracle inputs."""
    x86 = load_toml(X86_LEDGER_PATH)
    baseline = load_toml(BASELINE_CAPABILITIES_PATH)
    abi_manifest = json.loads(AARCH64_ABI_MANIFEST_PATH.read_text(encoding="utf-8"))
    require(isinstance(abi_manifest, dict), "AArch64 ABI manifest must be an object")

    require(x86.get("baseline_capability_ledger") == "compat/crabc-rs/coverage.toml", "x86 ledger baseline capability source changed")
    require(x86.get("baseline_platform") == "Linux/AArch64 little-endian", "x86 ledger baseline platform changed")
    policy = x86.get("policy")
    require(isinstance(policy, Mapping), "x86 ledger policy is missing")
    require(policy.get("public_support") is False, "inventory cannot be produced from a public x86 ledger")

    capability_entries = baseline.get("capability")
    require(isinstance(capability_entries, list), "AArch64 capability ledger has no capability list")
    baseline_capabilities: dict[str, Mapping[str, Any]] = {}
    for entry in capability_entries:
        require(isinstance(entry, Mapping), "AArch64 capability entry is invalid")
        identifier = entry.get("id")
        require(isinstance(identifier, str) and identifier, "AArch64 capability id is invalid")
        require(identifier not in baseline_capabilities, f"duplicate AArch64 capability {identifier}")
        baseline_capabilities[identifier] = entry

    families = x86.get("family")
    promotion = x86.get("promotion")
    require(isinstance(families, list) and isinstance(promotion, Mapping), "x86 ledger family/promotion contract is invalid")
    required_families = promotion.get("required_families")
    require(isinstance(required_families, list), "x86 promotion family roster is invalid")
    require([family.get("id") for family in families if isinstance(family, Mapping)] == required_families, "x86 family order no longer equals the closed promotion roster")

    owners: dict[str, Mapping[str, Any]] = {}
    selected_capabilities: set[str] = set()
    verified_record_ids: set[str] = set()
    family_rows: list[dict[str, Any]] = []
    selected_artifacts: list[dict[str, str]] = []
    for family in families:
        require(isinstance(family, Mapping), "x86 family entry is invalid")
        identifier = family.get("id")
        require(isinstance(identifier, str) and identifier, "x86 family id is invalid")
        capability_ids = family.get("capabilities")
        require(isinstance(capability_ids, list), f"x86 family {identifier} capability list is invalid")
        for capability in capability_ids:
            require(isinstance(capability, str), f"x86 family {identifier} has non-string capability")
            require(capability in baseline_capabilities, f"x86 family {identifier} references unknown AArch64 capability {capability}")
            require(capability not in owners, f"AArch64 capability {capability} is mapped by two x86 families")
            owners[capability] = family
        family_capability_set = set(capability_ids)
        for record in family.get("verified_slice", []) or []:
            require(isinstance(record, Mapping), f"x86 family {identifier} has invalid verified slice")
            record_id = record.get("id")
            require(
                isinstance(record_id, str) and record_id,
                f"x86 family {identifier} has a verified slice with an invalid id",
            )
            require(
                record_id not in verified_record_ids,
                f"duplicate verified record id: {record_id}",
            )
            verified_record_ids.add(record_id)
            values = record.get("capabilities")
            require(
                isinstance(values, list) and values,
                f"x86 verified slice {record_id} lacks capabilities",
            )
            require(
                all(isinstance(capability, str) and capability for capability in values),
                f"x86 verified slice {record_id} has an invalid capability",
            )
            require(
                len(values) == len(set(values)),
                f"x86 verified slice {record_id} duplicates a capability",
            )
            outside_family = sorted(set(values) - family_capability_set)
            require(
                not outside_family,
                "x86 verified slice "
                f"{record_id} selects a capability that escapes its owning family: "
                f"{', '.join(outside_family)}",
            )
            duplicate_selection = sorted(set(values) & selected_capabilities)
            require(
                not duplicate_selection,
                "x86 capability is selected by more than one verified slice: "
                f"{', '.join(duplicate_selection)}",
            )
            selected_capabilities.update(values)
        for record in family.get("verified_artifact", []) or []:
            require(isinstance(record, Mapping), f"x86 family {identifier} has invalid verified artifact")
            record_id = record.get("id")
            require(isinstance(record_id, str) and record_id, f"x86 family {identifier} verified artifact id is invalid")
            require(
                record_id not in verified_record_ids,
                f"duplicate verified record id: {record_id}",
            )
            verified_record_ids.add(record_id)
            require(
                "capabilities" not in record,
                f"x86 verified artifact {record_id} must not carry capabilities",
            )
            selected_artifacts.append({"family": identifier, "id": record_id})
        family_rows.append(
            {
                "id": identifier,
                "aarch64_gates": family.get("aarch64_gates"),
                "contract_state": family_state(family),
                "capability_count": len(capability_ids),
                "verified_slice_count": len(family.get("verified_slice", []) or []),
                "verified_artifact_count": len(family.get("verified_artifact", []) or []),
            }
        )
    require(set(owners) == set(baseline_capabilities), "x86 ledger no longer maps every AArch64 capability exactly once")

    capability_rows: list[dict[str, str]] = []
    for identifier, capability in sorted(baseline_capabilities.items()):
        family = owners[identifier]
        if family.get("status") == "foundation-verified":
            state = STATE_IMPLEMENTED
        elif identifier in selected_capabilities:
            state = STATE_SELECTED
        else:
            state = STATE_MISSING
        classification = capability.get("classification")
        require(isinstance(classification, str) and classification, f"AArch64 capability {identifier} classification is invalid")
        capability_rows.append(
            {
                "id": identifier,
                "aarch64_classification": classification,
                "x86_family": str(family["id"]),
                "contract_state": state,
            }
        )

    public_headers = sorted_unique_lines(X86_PUBLIC_HEADERS_PATH)
    baseline_headers = aarch64_public_headers(AARCH64_HEADERS_PATH)
    manifest_headers = abi_manifest.get("headers")
    require(isinstance(manifest_headers, Mapping), "AArch64 ABI manifest headers section is invalid")
    require(manifest_headers.get("public_records") == len(baseline_headers), "AArch64 ABI manifest/header TSV public count differs")
    require(public_headers == baseline_headers, "x86 public-header inventory no longer equals the pinned AArch64 public-header oracle")

    static_exports = sorted_unique_lines(X86_STATIC_EXPORTS_PATH, comments=True)
    candidate_symbols = baseline.get("dynamic_exports", {}).get("candidate_symbols")
    require(isinstance(candidate_symbols, list), "AArch64 dynamic export candidate set is missing")
    candidate_symbol_set = set(candidate_symbols)
    require(len(candidate_symbol_set) == len(candidate_symbols), "AArch64 dynamic export candidate set has duplicates")

    excluded = x86.get("excluded_surface")
    require(isinstance(excluded, list), "x86 ledger excluded surface is invalid")
    unsupported = []
    for entry in excluded:
        require(isinstance(entry, Mapping), "x86 excluded-surface entry is invalid")
        identifier = entry.get("id")
        reason = entry.get("reason")
        require(isinstance(identifier, str) and isinstance(reason, str), "x86 excluded-surface entry is incomplete")
        unsupported.append({"id": identifier, "reason": reason})

    state_counts = Counter(row["contract_state"] for row in capability_rows)
    family_state_counts = Counter(row["contract_state"] for row in family_rows)
    return {
        "schema": SCHEMA,
        "purpose": "Derived AArch64-to-x86 runtime contract inventory; evidence accounting only, never a promotion decision.",
        "source_digests": {
            "aarch64_abi_manifest": sha256(AARCH64_ABI_MANIFEST_PATH),
            "aarch64_headers": sha256(AARCH64_HEADERS_PATH),
            "aarch64_capability_ledger": sha256(BASELINE_CAPABILITIES_PATH),
            "x86_parity_ledger": sha256(X86_LEDGER_PATH),
            "x86_public_headers": sha256(X86_PUBLIC_HEADERS_PATH),
            "x86_static_c_exports": sha256(X86_STATIC_EXPORTS_PATH),
        },
        "baseline": {
            "platform": x86["baseline_platform"],
            "capability_count": len(capability_rows),
            "aarch64_dynamic_export_count": len(candidate_symbols),
            "aarch64_public_header_count": len(baseline_headers),
        },
        "x86_boundary": {
            "promotion_ready": False,
            "public_support": False,
            "promotion_family_count": len(family_rows),
            "selected_static_export_count": len(static_exports),
            "selected_static_exports_in_aarch64_dynamic_candidate_set": len(set(static_exports) & candidate_symbol_set),
        },
        "family_state_counts": dict(sorted(family_state_counts.items())),
        "capability_state_counts": dict(sorted(state_counts.items())),
        "families": family_rows,
        "capabilities": capability_rows,
        "selected_private_artifacts": sorted(selected_artifacts, key=lambda row: (row["family"], row["id"])),
        "unsupported_contracts": unsupported,
    }


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def validate_inventory() -> dict[str, Any]:
    actual = build_inventory()
    try:
        expected = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InventoryError(f"cannot read checked inventory: {error}") from error
    require(expected == actual, "derived inventory drifted; regenerate it after reviewing the underlying AArch64/x86 contract change")
    require(actual["x86_boundary"]["promotion_ready"] is False, "inventory must retain promotion_ready=false")
    require(actual["x86_boundary"]["public_support"] is False, "inventory must retain public_support=false")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the reviewed derived inventory snapshot")
    arguments = parser.parse_args()
    if arguments.write:
        INVENTORY_PATH.write_text(canonical_json(build_inventory()), encoding="utf-8")
    report = validate_inventory()
    print(
        "x86 AArch64 parity inventory: PASS "
        f"({report['baseline']['capability_count']} capabilities; "
        f"implemented={report['capability_state_counts'].get(STATE_IMPLEMENTED, 0)}; "
        f"selected={report['capability_state_counts'].get(STATE_SELECTED, 0)}; "
        f"missing={report['capability_state_counts'].get(STATE_MISSING, 0)}; "
        "promotion_ready=False; public_support=False)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InventoryError as error:
        raise SystemExit(f"x86 AArch64 parity inventory: ERROR: {error}") from error
