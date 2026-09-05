#!/usr/bin/env python3
"""Audit ordinary archive extraction for every selected x86 callable provider.

The existing default-archive audit deliberately remains red while public
callables are split between the default archive, explicit feature archives,
and work not yet provided.  This companion audit discharges the first two
classes without mistaking a nonempty default-archive complement for failure.
It records the genuinely unprovided names as the finite remaining closure
blocker.

Each buildable feature profile compares its exact Cargo feature request with
the roster's dependency-only baseline in isolated archives.  The one
``x86-crypt-allocator-composition`` profile is topology-only: its direct
baseline pair is intentionally rejected, so its dedicated provider runner
remains the semantic evidence and this audit verifies only that it has no
callable delta contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from feature_archive_roster import FeatureArchive, load_feature_archive_roster
from header_callable_linkage_audit import (
    INVENTORY_PATH,
    INVENTORY_SCHEMA,
    STATIC_EXPORTS_PATH,
    callable_provider_partition,
    candidate_external_symbols,
    global_defined_symbols,
    load_json,
    load_static_exports,
    require,
    sha256_file,
)


SCHEMA = "crabc.x86_64-header-callable-provider-linkage-audit/v1"

# This profile deliberately names a valid topology that cannot be expressed as
# a direct baseline Cargo request: static_c_abi.rs rejects x86-crypt together
# with x86-allocator-runtime unless this feature names their provider contract.
TOPOLOGY_ONLY_PROFILE = "x86-crypt-allocator-composition"
TOPOLOGY_ONLY_BASELINE = ("x86-allocator-runtime", "x86-crypt")


class ProviderLinkageAuditError(ValueError):
    """The selected-provider closure inputs are not a finite safe contract."""


def provider_require(condition: bool, message: str) -> None:
    try:
        require(condition, message)
    except ValueError as error:
        raise ProviderLinkageAuditError(str(error)) from error


def safe_archive(path: Path, location: str) -> Path:
    provider_require(path.is_file() and not path.is_symlink(), f"{location} is unsafe: {path}")
    return path


def parse_profile_assignment(values: Sequence[str], location: str) -> dict[str, Path]:
    parsed: dict[str, Path] = {}
    for raw in values:
        identifier, separator, raw_path = raw.partition("=")
        provider_require(separator == "=" and identifier and raw_path, f"{location} must be ID=PATH")
        provider_require(identifier not in parsed, f"{location} duplicates {identifier}")
        parsed[identifier] = Path(raw_path)
    return parsed


def global_symbol_details(path: Path, readelf: str) -> dict[str, list[dict[str, str]]]:
    result = subprocess.run(
        [readelf, "--symbols", "--wide", str(path)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    provider_require(result.returncode == 0, f"readelf could not read {path}: {result.stderr.strip()}")
    details: dict[str, list[dict[str, str]]] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].endswith(":"):
            continue
        symbol_type, binding, visibility, section, name = fields[3:8]
        if symbol_type != "FUNC" or name == "":
            continue
        details.setdefault(name, []).append(
            {
                "binding": binding,
                "section": section,
                "value": fields[1],
                "visibility": visibility,
            }
        )
    return details


def extract_symbol(
    archive: Path,
    symbols: Sequence[str],
    linker: str,
    nm: str,
    work_dir: Path,
) -> tuple[dict[str, Any], Path | None]:
    provider_require(symbols, "ordinary extraction needs at least one symbol")
    stem = "-".join(symbols)
    output = work_dir / f"extract-{hashlib.sha256(stem.encode('utf-8')).hexdigest()[:16]}.o"
    command = [linker, "-r", "--no-undefined"]
    command.extend(f"--undefined={symbol}" for symbol in symbols)
    command.extend(["-o", str(output), str(archive)])
    result = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    requested = list(symbols)
    if result.returncode != 0:
        diagnostic = next(
            (line.strip() for line in result.stderr.splitlines() if line.strip()),
            "linker produced no diagnostic",
        )
        return (
            {
                "detail": diagnostic,
                "status": "link-failed",
                "symbols": requested,
            },
            None,
        )
    defined = global_defined_symbols(output, nm)
    missing = sorted(set(symbols) - defined)
    if missing:
        return (
            {
                "detail": "ordinary archive extraction did not define " + ", ".join(missing),
                "status": "not-extracted",
                "symbols": requested,
            },
            None,
        )
    return (
        {
            "detail": "ordinary ld -r extraction defined the requested function(s)",
            "status": "extracted",
            "symbols": requested,
        },
        output,
    )


def extract_many(
    archive: Path,
    symbols: Sequence[str],
    linker: str,
    nm: str,
    work_dir: Path,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for symbol in symbols:
        record, _ = extract_symbol(archive, (symbol,), linker, nm, work_dir)
        records.append(
            {
                "detail": record["detail"],
                "status": record["status"],
                "symbol": symbol,
            }
        )
    return records


def alias_record(
    archive: Path,
    name: str,
    target: str,
    binding: str,
    linker: str,
    nm: str,
    readelf: str,
    work_dir: Path,
) -> dict[str, str]:
    provider_require(binding == "weak-same-address", f"unsupported alias binding for {name}")
    extraction, output = extract_symbol(archive, (name, target), linker, nm, work_dir)
    if output is None:
        return {
            "detail": extraction["detail"],
            "name": name,
            "status": extraction["status"],
            "target": target,
        }
    details = global_symbol_details(output, readelf)
    aliases = [
        entry
        for entry in details.get(name, [])
        if entry["binding"] == "WEAK"
    ]
    targets = [
        entry
        for entry in details.get(target, [])
        if entry["binding"] == "GLOBAL"
    ]
    for alias in aliases:
        for target_entry in targets:
            if alias["value"] == target_entry["value"] and alias["section"] == target_entry["section"]:
                return {
                    "detail": "weak function alias and global target share one extracted address",
                    "name": name,
                    "status": "verified",
                    "target": target,
                }
    return {
        "detail": "expected weak function alias and global same-address target were not both present",
        "name": name,
        "status": "binding-mismatch",
        "target": target,
    }


def feature_rows(
    inventory_partition: Mapping[str, Any],
    roster: Sequence[FeatureArchive],
) -> tuple[dict[str, Mapping[str, Any]], dict[str, Mapping[str, Any]]]:
    verified_raw = inventory_partition.get("verified_feature_archives")
    replacement_raw = inventory_partition.get("replacement_variants")
    provider_require(isinstance(verified_raw, list), "inventory verified feature providers are invalid")
    provider_require(isinstance(replacement_raw, list), "inventory replacement variants are invalid")
    verified: dict[str, Mapping[str, Any]] = {}
    for row in verified_raw:
        provider_require(isinstance(row, Mapping), "inventory verified feature provider row is invalid")
        identifier = row.get("id")
        provider_require(isinstance(identifier, str) and identifier and identifier not in verified, "inventory verified feature provider id is invalid")
        verified[identifier] = row
    replacements: dict[str, Mapping[str, Any]] = {}
    for row in replacement_raw:
        provider_require(isinstance(row, Mapping), "inventory replacement variant row is invalid")
        identifier = row.get("id")
        provider_require(isinstance(identifier, str) and identifier and identifier not in replacements, "inventory replacement variant id is invalid")
        replacements[identifier] = row
    expected = {row.identifier for row in roster if row.state == "verified"}
    provider_require(set(verified) == expected, "inventory verified provider ids drift from the feature archive roster")
    # The inventory records every declared replacement variant, including
    # unverified profiles. This selected-provider audit only builds verified
    # archives below, but it must still reject an inventory that omits or
    # invents an unverified replacement ownership record.
    expected_replacements = {row.identifier for row in roster if row.replacement_callables}
    provider_require(set(replacements) == expected_replacements, "inventory replacement provider ids drift from the feature archive roster")
    return verified, replacements


def profile_surface(archive: Path, visible_symbols: set[str], nm: str) -> set[str]:
    return global_defined_symbols(archive, nm) & visible_symbols


def profile_report(
    feature: FeatureArchive,
    provider_row: Mapping[str, Any],
    replacement_row: Mapping[str, Any] | None,
    archives: Mapping[str, Path],
    visible_symbols: set[str],
    linker: str,
    nm: str,
    readelf: str,
    work_dir: Path,
) -> tuple[dict[str, Any], list[str]]:
    members = provider_row.get("members")
    provider_require(isinstance(members, list), f"feature {feature.identifier} provider members are invalid")
    provider_require(
        tuple(members) == feature.additive_callables,
        f"feature {feature.identifier} provider members drift from the roster",
    )
    aliases = provider_row.get("aliases")
    provider_require(isinstance(aliases, list), f"feature {feature.identifier} provider aliases are invalid")
    expected_aliases = [
        {"binding": alias.binding, "name": alias.name, "target": alias.target}
        for alias in feature.aliases
    ]
    provider_require(aliases == expected_aliases, f"feature {feature.identifier} provider aliases drift from the roster")
    expected_replacements = list(feature.replacement_callables)
    if expected_replacements:
        provider_require(replacement_row is not None, f"feature {feature.identifier} replacement provider is missing")
        replacement_members = replacement_row.get("members")
        provider_require(
            replacement_members == expected_replacements,
            f"feature {feature.identifier} replacement members drift from the roster",
        )
    else:
        provider_require(replacement_row is None, f"feature {feature.identifier} unexpectedly has replacement members")

    enabled = safe_archive(archives["enabled"], f"feature {feature.identifier} enabled archive")
    if feature.identifier == TOPOLOGY_ONLY_PROFILE:
        provider_require(
            feature.baseline_features == TOPOLOGY_ONLY_BASELINE
            and not feature.additive_callables
            and not feature.replacement_callables
            and not feature.aliases,
            "the topology-only composition profile drifted from its no-callable contract",
        )
        provider_require(set(archives) == {"enabled"}, "topology-only feature profile must not build its rejected baseline pair")
        return (
            {
                "aliases": [],
                "candidate_external_delta": [],
                "detail": "named composition profile has no callable delta; its dedicated provider runner owns the rejected-pair and allocation-provider proof",
                "id": feature.identifier,
                "mode": "topology-only-dedicated-evidence",
                "status": "delegated",
            },
            [],
        )

    provider_require(set(archives) == {"baseline", "enabled"}, f"feature {feature.identifier} needs isolated baseline and enabled archives")
    baseline = safe_archive(archives["baseline"], f"feature {feature.identifier} baseline archive")
    baseline_surface = profile_surface(baseline, visible_symbols, nm)
    enabled_surface = profile_surface(enabled, visible_symbols, nm)
    removed = sorted(baseline_surface - enabled_surface)
    delta = sorted(enabled_surface - baseline_surface)
    expected_delta = sorted(set(feature.additive_callables) | {alias.name for alias in feature.aliases if alias.name not in baseline_surface})
    failures: list[str] = []
    if removed:
        failures.append("enabled profile removes visible callable(s): " + ", ".join(removed))
    if delta != expected_delta:
        failures.append(
            "enabled profile callable delta is "
            + ", ".join(delta)
            + "; expected "
            + ", ".join(expected_delta)
        )
    additive_extraction = extract_many(enabled, feature.additive_callables, linker, nm, work_dir)
    for entry in additive_extraction:
        if entry["status"] != "extracted":
            failures.append(f"additive {entry['symbol']} did not extract ordinarily")
    baseline_replacement_extraction = extract_many(
        baseline, feature.replacement_callables, linker, nm, work_dir
    )
    replacement_extraction = extract_many(
        enabled, feature.replacement_callables, linker, nm, work_dir
    )
    for entry in [*baseline_replacement_extraction, *replacement_extraction]:
        if entry["status"] != "extracted":
            failures.append(f"replacement {entry['symbol']} did not extract ordinarily")
    alias_checks = [
        alias_record(
            enabled,
            alias.name,
            alias.target,
            alias.binding,
            linker,
            nm,
            readelf,
            work_dir,
        )
        for alias in feature.aliases
    ]
    for entry in alias_checks:
        if entry["status"] != "verified":
            failures.append(f"alias {entry['name']} failed binding verification")
    return (
        {
            "additive_extraction": additive_extraction,
            "aliases": alias_checks,
            "baseline_candidate_external_symbols": sorted(baseline_surface),
            "baseline_replacement_extraction": baseline_replacement_extraction,
            "candidate_external_delta": delta,
            "enabled_candidate_external_symbols": sorted(enabled_surface),
            "id": feature.identifier,
            "mode": "isolated-baseline-and-enabled-archives",
            "replacement_extraction": replacement_extraction,
            "status": "verified" if not failures else "incomplete",
        },
        failures,
    )


def audit_provider_closure(
    *,
    inventory: Mapping[str, Any],
    static_exports: Sequence[str],
    default_archive: Path,
    roster: Sequence[FeatureArchive],
    profile_archives: Mapping[str, Mapping[str, Path]],
    linker: str = "ld",
    nm: str = "nm",
    readelf: str = "readelf",
) -> dict[str, Any]:
    """Return the selected-provider closure report without hiding red names."""
    provider_require(shutil.which(linker) is not None, f"linker is unavailable: {linker}")
    provider_require(shutil.which(nm) is not None, f"nm is unavailable: {nm}")
    provider_require(shutil.which(readelf) is not None, f"readelf is unavailable: {readelf}")
    default_archive = safe_archive(default_archive, "default static archive")
    external = candidate_external_symbols(inventory)
    provider_partition, provider_counts = callable_provider_partition(
        inventory, external, static_exports
    )
    verified_rows, replacement_rows = feature_rows(provider_partition, roster)
    verified_roster = tuple(row for row in roster if row.state == "verified")
    provider_require(
        set(profile_archives) == {row.identifier for row in verified_roster},
        "profile archives must cover every and only verified feature profile",
    )
    default_symbols = set(provider_partition["default_static"]["members"])
    visible_symbols = set(external)
    for feature in verified_roster:
        visible_symbols.update(feature.additive_callables)
        visible_symbols.update(feature.replacement_callables)
        visible_symbols.update(alias.name for alias in feature.aliases)

    with tempfile.TemporaryDirectory(prefix="crabc-x86-header-callable-provider-linkage.") as temporary:
        work_dir = Path(temporary)
        default_extraction = extract_many(
            default_archive, sorted(default_symbols), linker, nm, work_dir
        )
        failures = [
            f"default static {entry['symbol']} did not extract ordinarily"
            for entry in default_extraction
            if entry["status"] != "extracted"
        ]
        profiles: list[dict[str, Any]] = []
        for feature in verified_roster:
            row, profile_failures = profile_report(
                feature,
                verified_rows[feature.identifier],
                replacement_rows.get(feature.identifier),
                profile_archives[feature.identifier],
                visible_symbols,
                linker,
                nm,
                readelf,
                work_dir,
            )
            profiles.append(row)
            failures.extend(f"{feature.identifier}: {failure}" for failure in profile_failures)

    unprovided = provider_partition["unprovided"]["members"]
    declared_unverified = provider_partition["declared_unverified_feature_archives"]
    incomplete_reasons = list(failures)
    if declared_unverified:
        incomplete_reasons.append("one or more candidate external callables have only an unverified feature provider")
    if unprovided:
        incomplete_reasons.append("one or more candidate external callables remain unprovided")
    selected_provider_closure_complete = not failures
    complete = selected_provider_closure_complete and not declared_unverified and not unprovided
    return {
        "callable_provider_partition": provider_partition,
        "default_static": {
            "extraction": default_extraction,
            "member_count": len(default_symbols),
        },
        "external_callable_count": len(external),
        "feature_profiles": profiles,
        "inventory_schema": INVENTORY_SCHEMA,
        "inventory_static_export_digest": inventory.get("inputs", {}).get("static_c_abi_exports_sha256"),
        "schema": SCHEMA,
        "scope": {
            "family_promotion": False,
            "full_callable_closure": False,
            "public_support": False,
            "selected_feature_profiles_extracted": True,
            "uses_whole_archive": False,
        },
        "summary": {
            "callable_provider_counts": provider_counts,
            "complete": complete,
            "incomplete_reasons": incomplete_reasons,
            "selected_provider_closure_complete": selected_provider_closure_complete,
            "topology_only_profile_count": sum(
                row["mode"] == "topology-only-dedicated-evidence" for row in profiles
            ),
            "unprovided_callable_count": len(unprovided),
            "verified_feature_profile_count": len(verified_roster),
        },
        "unprovided": {
            "kind": "candidate-external-callables-without-a-verified-archive-provider",
            "members": unprovided,
        },
    }


def audit_inventory_file(
    inventory_path: Path,
    static_exports_path: Path,
    default_archive: Path,
    profile_archives: Mapping[str, Mapping[str, Path]],
    *,
    roster: Sequence[FeatureArchive] | None = None,
    linker: str = "ld",
    nm: str = "nm",
    readelf: str = "readelf",
) -> dict[str, Any]:
    inventory = load_json(inventory_path)
    provider_require(
        inventory.get("inputs", {}).get("static_c_abi_exports_sha256")
        == sha256_file(static_exports_path),
        "inventory was generated against a different static export ratchet; regenerate it before audit",
    )
    return audit_provider_closure(
        inventory=inventory,
        static_exports=load_static_exports(static_exports_path),
        default_archive=default_archive,
        roster=load_feature_archive_roster() if roster is None else roster,
        profile_archives=profile_archives,
        linker=linker,
        nm=nm,
        readelf=readelf,
    )


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=INVENTORY_PATH)
    parser.add_argument("--static-exports", type=Path, default=STATIC_EXPORTS_PATH)
    parser.add_argument("--default-archive", type=Path, required=True)
    parser.add_argument("--profile-baseline", action="append", default=[], metavar="ID=PATH")
    parser.add_argument("--profile-enabled", action="append", default=[], metavar="ID=PATH")
    parser.add_argument("--linker", default="ld")
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--readelf", default="readelf")
    parser.add_argument("--output", type=Path, help="write canonical JSON to this exact path")
    parsed = parser.parse_args(arguments)
    baselines = parse_profile_assignment(parsed.profile_baseline, "--profile-baseline")
    enabled = parse_profile_assignment(parsed.profile_enabled, "--profile-enabled")
    profile_archives: dict[str, dict[str, Path]] = {}
    for identifier in sorted(set(baselines) | set(enabled)):
        entries: dict[str, Path] = {}
        if identifier in baselines:
            entries["baseline"] = baselines[identifier]
        if identifier in enabled:
            entries["enabled"] = enabled[identifier]
        profile_archives[identifier] = entries
    report = audit_inventory_file(
        parsed.inventory,
        parsed.static_exports,
        parsed.default_archive,
        profile_archives,
        linker=parsed.linker,
        nm=parsed.nm,
        readelf=parsed.readelf,
    )
    rendered = canonical_json(report)
    if parsed.output is None:
        sys.stdout.write(rendered)
    else:
        provider_require(not parsed.output.is_symlink(), f"audit output path is a symlink: {parsed.output}")
        parsed.output.write_text(rendered, encoding="utf-8")
    return 0 if report["summary"]["selected_provider_closure_complete"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProviderLinkageAuditError, ValueError) as error:
        raise SystemExit(f"x86 header callable provider linkage audit: ERROR: {error}") from error
