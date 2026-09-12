#!/usr/bin/env python3
"""Shared contract for explicit Linux/x86-64 feature-archive ownership.

The selected default ``libc.a`` is intentionally narrower than every native
feature archive.  This module makes those opt-in profiles explicit without
inferring ownership from Cargo names or prose.  The parity ledger owns one row
for every ``x86-*`` libc feature; callers can then distinguish a verified
feature provider from a merely declared implementation.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
CARGO_MANIFEST_PATH = ROOT / "libc" / "Cargo.toml"
LEDGER_PATH = ROOT / "compat" / "x86_64" / "parity.toml"
VALID_STATES = {"planned", "verified"}
VALID_ALIAS_BINDINGS = {"weak-same-address"}
SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
COMMAND_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class FeatureArchiveRosterError(ValueError):
    """The feature-archive ownership roster is not a safe finite contract."""


@dataclass(frozen=True)
class ArchiveAlias:
    """One documented selected ELF alias in an archive profile."""

    name: str
    target: str
    binding: str


@dataclass(frozen=True)
class FeatureArchive:
    """One Cargo-selected archive profile and its callable provider delta.

    ``additive_callables`` and ``replacement_callables`` name installed-header
    declarations. ``abi_only_callables`` names archive functions which
    intentionally have no installed declaration and therefore stay out of the
    header provider partition.
    """

    identifier: str
    state: str
    evidence_record: str | None
    runner: str
    dispatch_command: str | None
    baseline_features: tuple[str, ...]
    enabled_features: tuple[str, ...]
    additive_callables: tuple[str, ...]
    replacement_callables: tuple[str, ...]
    aliases: tuple[ArchiveAlias, ...]
    feature_selection_source: str | None = None
    abi_only_callables: tuple[str, ...] = ()


@dataclass(frozen=True)
class CallableProviderPartition:
    """Exclusive candidate-callable provider accounting plus replacements."""

    default_static: tuple[str, ...]
    verified_feature_archives: tuple[tuple[FeatureArchive, tuple[str, ...]], ...]
    declared_unverified_feature_archives: tuple[tuple[FeatureArchive, tuple[str, ...]], ...]
    unprovided: tuple[str, ...]
    replacement_variants: tuple[tuple[FeatureArchive, tuple[str, ...]], ...]

    def as_report(self) -> dict[str, Any]:
        def provider_row(archive: FeatureArchive, members: tuple[str, ...]) -> dict[str, Any]:
            return {
                "aliases": [
                    {
                        "binding": alias.binding,
                        "name": alias.name,
                        "target": alias.target,
                    }
                    for alias in archive.aliases
                ],
                "evidence_record": archive.evidence_record,
                "id": archive.identifier,
                "members": list(members),
                "runner": archive.runner,
                "state": archive.state,
            }

        return {
            "declared_unverified_feature_archives": [
                provider_row(archive, members)
                for archive, members in self.declared_unverified_feature_archives
            ],
            "default_static": {"members": list(self.default_static)},
            "kind": "candidate-external-callable-feature-archive-provider-partition",
            "replacement_variants": [
                {
                    "id": archive.identifier,
                    "members": list(members),
                    "state": archive.state,
                }
                for archive, members in self.replacement_variants
            ],
            "unprovided": {"members": list(self.unprovided)},
            "verified_feature_archives": [
                provider_row(archive, members)
                for archive, members in self.verified_feature_archives
            ],
        }

    def counts(self) -> dict[str, int]:
        return {
            "declared_unverified_feature_archives": sum(
                len(members) for _, members in self.declared_unverified_feature_archives
            ),
            "default_static": len(self.default_static),
            "unprovided": len(self.unprovided),
            "verified_feature_archives": sum(
                len(members) for _, members in self.verified_feature_archives
            ),
        }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FeatureArchiveRosterError(message)


def string_list(value: object, location: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    require(isinstance(value, list), f"{location} must be an array")
    values: list[str] = []
    for index, item in enumerate(value):
        require(isinstance(item, str) and item, f"{location}[{index}] is invalid")
        values.append(item)
    if not allow_empty:
        require(values, f"{location} must not be empty")
    require(values == sorted(values), f"{location} must be ASCII sorted")
    require(len(values) == len(set(values)), f"{location} contains duplicates")
    return tuple(values)


def require_symbol(value: object, location: str) -> str:
    require(isinstance(value, str) and SYMBOL_RE.fullmatch(value) is not None, f"{location} is invalid")
    return value


def load_cargo_x86_features(path: Path = CARGO_MANIFEST_PATH) -> dict[str, tuple[str, ...]]:
    try:
        with path.open("rb") as stream:
            manifest = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise FeatureArchiveRosterError(f"cannot load Cargo feature manifest {path}: {error}") from error
    features = manifest.get("features")
    require(isinstance(features, Mapping), "libc Cargo feature table is missing")
    result: dict[str, tuple[str, ...]] = {}
    for identifier, dependencies in features.items():
        if not isinstance(identifier, str) or not identifier.startswith("x86-"):
            continue
        require(isinstance(dependencies, list), f"libc Cargo feature {identifier} is invalid")
        checked: list[str] = []
        for index, dependency in enumerate(dependencies):
            require(
                isinstance(dependency, str) and dependency,
                f"libc Cargo feature {identifier}[{index}] is invalid",
            )
            checked.append(dependency)
        result[identifier] = tuple(checked)
    require(result, "libc Cargo feature table has no x86 feature profiles")
    return result


def feature_closure(
    roots: Iterable[str], cargo_features: Mapping[str, Sequence[str]]
) -> tuple[str, ...]:
    """Resolve only target-local x86 feature dependencies from Cargo."""

    resolved: set[str] = set()

    def visit(identifier: str) -> None:
        require(identifier in cargo_features, f"unknown x86 Cargo feature {identifier}")
        if identifier in resolved:
            return
        resolved.add(identifier)
        for dependency in cargo_features[identifier]:
            if dependency.startswith("x86-"):
                visit(dependency)

    for identifier in roots:
        visit(identifier)
    return tuple(sorted(resolved))


def parse_feature_archive_roster(
    raw_rows: object, cargo_features: Mapping[str, Sequence[str]]
) -> tuple[FeatureArchive, ...]:
    require(isinstance(raw_rows, list) and raw_rows, "feature archive roster is missing")
    rows: list[FeatureArchive] = []
    identifiers: set[str] = set()
    common_keys = {
        "id",
        "state",
        "runner",
        "baseline_features",
        "enabled_features",
        "additive_callables",
        "replacement_callables",
        "aliases",
    }
    for index, raw in enumerate(raw_rows):
        location = f"feature_archive[{index}]"
        require(isinstance(raw, Mapping), f"{location} must be a table")
        identifier = raw.get("id")
        require(
            isinstance(identifier, str) and identifier.startswith("x86-") and identifier in cargo_features,
            f"{location}.id is not a declared x86 Cargo feature",
        )
        require(identifier not in identifiers, f"feature archive {identifier} is duplicated")
        identifiers.add(identifier)
        state = raw.get("state")
        require(state in VALID_STATES, f"{location}.state is invalid")
        expected_keys = set(common_keys)
        if "abi_only_callables" in raw:
            expected_keys.add("abi_only_callables")
        if state == "verified":
            expected_keys.update({"evidence_record", "dispatch_command"})
        else:
            expected_keys.add("feature_selection_source")
        require(set(raw) == expected_keys, f"{location} keys drifted")

        runner = raw.get("runner")
        require(isinstance(runner, str) and runner and not Path(runner).is_absolute(), f"{location}.runner is invalid")
        runner_path = Path(runner)
        require(".." not in runner_path.parts, f"{location}.runner escapes the repository")

        evidence_record: str | None = None
        dispatch_command: str | None = None
        feature_selection_source: str | None = None
        if state == "verified":
            evidence_record = raw.get("evidence_record")
            require(
                isinstance(evidence_record, str) and evidence_record,
                f"{location}.evidence_record is invalid",
            )
            dispatch_command = raw.get("dispatch_command")
            require(
                isinstance(dispatch_command, str) and COMMAND_RE.fullmatch(dispatch_command) is not None,
                f"{location}.dispatch_command is invalid",
            )
        else:
            feature_selection_source = raw.get("feature_selection_source")
            require(
                isinstance(feature_selection_source, str)
                and feature_selection_source
                and not Path(feature_selection_source).is_absolute(),
                f"{location}.feature_selection_source is invalid",
            )
            require(
                ".." not in Path(feature_selection_source).parts,
                f"{location}.feature_selection_source escapes the repository",
            )

        baseline_features = string_list(raw.get("baseline_features"), f"{location}.baseline_features", allow_empty=True)
        enabled_features = string_list(raw.get("enabled_features"), f"{location}.enabled_features")
        require(enabled_features == (identifier,), f"{location}.enabled_features must select only its id")
        for feature in (*baseline_features, *enabled_features):
            require(feature in cargo_features, f"{location} names unknown Cargo feature {feature}")

        additive_callables = string_list(raw.get("additive_callables"), f"{location}.additive_callables", allow_empty=True)
        replacement_callables = string_list(raw.get("replacement_callables"), f"{location}.replacement_callables", allow_empty=True)
        abi_only_callables: tuple[str, ...] = ()
        if "abi_only_callables" in raw:
            abi_only_callables = string_list(
                raw.get("abi_only_callables"), f"{location}.abi_only_callables"
            )
        for name in (*additive_callables, *replacement_callables, *abi_only_callables):
            require_symbol(name, f"{location} callable {name}")
        require(
            not set(additive_callables) & set(replacement_callables),
            f"{location} overlaps additive and replacement callables",
        )
        require(
            not set(abi_only_callables) & set(additive_callables),
            f"{location} overlaps ABI-only and additive callables",
        )
        require(
            not set(abi_only_callables) & set(replacement_callables),
            f"{location} overlaps ABI-only and replacement callables",
        )

        raw_aliases = raw.get("aliases")
        require(isinstance(raw_aliases, list), f"{location}.aliases must be an array")
        aliases: list[ArchiveAlias] = []
        alias_names: set[str] = set()
        for alias_index, raw_alias in enumerate(raw_aliases):
            alias_location = f"{location}.aliases[{alias_index}]"
            require(isinstance(raw_alias, Mapping), f"{alias_location} must be a table")
            require(set(raw_alias) == {"name", "target", "binding"}, f"{alias_location} keys drifted")
            name = require_symbol(raw_alias.get("name"), f"{alias_location}.name")
            target = require_symbol(raw_alias.get("target"), f"{alias_location}.target")
            binding = raw_alias.get("binding")
            require(binding in VALID_ALIAS_BINDINGS, f"{alias_location}.binding is invalid")
            require(name not in alias_names, f"{location}.aliases repeats {name}")
            alias_names.add(name)
            aliases.append(ArchiveAlias(name=name, target=target, binding=str(binding)))
        require(
            [alias.name for alias in aliases] == sorted(alias.name for alias in aliases),
            f"{location}.aliases must be ASCII sorted by name",
        )
        for name in abi_only_callables:
            require(
                name not in alias_names,
                f"{location} ABI-only callable {name} is also an alias name",
            )

        rows.append(
            FeatureArchive(
                identifier=identifier,
                state=str(state),
                evidence_record=evidence_record,
                runner=runner,
                dispatch_command=dispatch_command,
                baseline_features=baseline_features,
                enabled_features=enabled_features,
                additive_callables=additive_callables,
                replacement_callables=replacement_callables,
                aliases=tuple(aliases),
                feature_selection_source=feature_selection_source,
                abi_only_callables=abi_only_callables,
            )
        )

    require(
        {row.identifier for row in rows} == set(cargo_features),
        "feature archive roster must cover every and only x86 Cargo feature",
    )
    require(
        tuple(row.identifier for row in rows) == tuple(cargo_features),
        "feature archive roster order must match libc Cargo feature order",
    )
    for row in rows:
        enabled_closure = set(feature_closure(row.enabled_features, cargo_features))
        baseline_closure = set(feature_closure(row.baseline_features, cargo_features))
        expected_baseline = enabled_closure - {row.identifier}
        require(
            baseline_closure == expected_baseline,
            f"feature archive {row.identifier} baseline does not match its Cargo feature dependency closure",
        )
    return tuple(rows)


def load_feature_archive_roster(
    ledger_path: Path = LEDGER_PATH,
    cargo_manifest_path: Path = CARGO_MANIFEST_PATH,
) -> tuple[FeatureArchive, ...]:
    try:
        with ledger_path.open("rb") as stream:
            ledger = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise FeatureArchiveRosterError(f"cannot load feature archive ledger {ledger_path}: {error}") from error
    return parse_feature_archive_roster(
        ledger.get("feature_archive"), load_cargo_x86_features(cargo_manifest_path)
    )


def selected_baseline_callables(
    archive: FeatureArchive, rows: Sequence[FeatureArchive], static_exports: Iterable[str]
) -> set[str]:
    """Resolve only providers already selected by an archive's dependencies.

    A replacement preserves the unique original provider in callable accounting.
    Its variant can replace either a default symbol or a dependency's addition;
    a provider in an unrelated feature cannot authorize that replacement.
    """
    by_id = {row.identifier: row for row in rows}
    selected = set(static_exports)
    pending = list(archive.baseline_features)
    visited: set[str] = set()
    while pending:
        identifier = pending.pop()
        if identifier in visited:
            continue
        require(identifier in by_id, f"selected baseline omits feature {identifier}")
        visited.add(identifier)
        dependency = by_id[identifier]
        selected.update(dependency.additive_callables)
        selected.update(dependency.abi_only_callables)
        pending.extend(dependency.baseline_features)
    return selected


def validate_abi_only_callable_ownership(
    rows: Sequence[FeatureArchive],
    *,
    static_exports: Iterable[str],
    candidate_callables: Iterable[str] | None = None,
) -> None:
    """Keep non-header function providers out of every header ownership route.

    Alias *names* are weak public identities and cannot also name an ABI-only
    provider. An alias target remains eligible: it is the provider side of a
    source-shaped alias group, not an alias identity itself.
    """

    static_export_set = set(static_exports)
    candidate_set = None if candidate_callables is None else set(candidate_callables)
    header_owners: dict[str, set[str]] = {}
    alias_owners: dict[str, set[str]] = {}
    for row in rows:
        for name in (*row.additive_callables, *row.replacement_callables):
            header_owners.setdefault(name, set()).add(row.identifier)
        for alias in row.aliases:
            alias_owners.setdefault(alias.name, set()).add(row.identifier)

    abi_only_owners: dict[str, str] = {}
    for row in rows:
        for name in row.abi_only_callables:
            require_symbol(name, f"feature archive {row.identifier} ABI-only callable {name}")
            require(
                name not in static_export_set,
                f"feature archive {row.identifier} ABI-only callable {name} is already default-static",
            )
            require(
                candidate_set is None or name not in candidate_set,
                f"feature archive {row.identifier} ABI-only callable {name} is header-declared",
            )
            header_owners_for_name = header_owners.get(name, set())
            require(
                not header_owners_for_name,
                f"feature archive {row.identifier} ABI-only callable {name} overlaps header callable ownership in "
                + ", ".join(sorted(header_owners_for_name)),
            )
            alias_owners_for_name = alias_owners.get(name, set())
            require(
                not alias_owners_for_name,
                f"feature archive {row.identifier} ABI-only callable {name} is also an alias name in "
                + ", ".join(sorted(alias_owners_for_name)),
            )
            previous = abi_only_owners.setdefault(name, row.identifier)
            require(
                previous == row.identifier,
                f"ABI-only callable {name} has multiple feature owners",
            )

    for row in rows:
        if not row.abi_only_callables:
            continue
        baseline = selected_baseline_callables(row, rows, static_export_set)
        for name in row.abi_only_callables:
            require(
                name not in baseline,
                f"feature archive {row.identifier} ABI-only callable {name} is already selected by its dependency baseline",
            )


def validate_ledger_bindings(
    rows: Sequence[FeatureArchive],
    *,
    static_exports: Iterable[str],
    verified_records: Mapping[str, Mapping[str, Any]],
    dispatcher_path: Path,
) -> dict[str, int]:
    """Bind verified rows to existing ledger evidence and runner entry points."""

    static_export_set = set(static_exports)
    require(static_export_set, "static export ratchet is empty")
    validate_abi_only_callable_ownership(rows, static_exports=static_export_set)
    require(dispatcher_path.is_file() and not dispatcher_path.is_symlink(), "x86 dispatcher is unsafe")
    dispatcher = dispatcher_path.read_text(encoding="utf-8")
    additive_owners: dict[str, str] = {}
    alias_owners: dict[str, str] = {}
    verified_count = 0
    planned_count = 0
    for row in rows:
        runner_path = ROOT / row.runner
        require(runner_path.is_file() and not runner_path.is_symlink(), f"feature archive {row.identifier} runner is missing")
        runner_source = runner_path.read_text(encoding="utf-8")
        if row.feature_selection_source is None:
            require(
                row.identifier in runner_source,
                f"feature archive {row.identifier} runner does not select its Cargo feature",
            )
        else:
            selection_path = ROOT / row.feature_selection_source
            require(
                selection_path.is_file() and not selection_path.is_symlink(),
                f"feature archive {row.identifier} feature selection source is missing",
            )
            require(
                row.feature_selection_source in runner_source,
                f"feature archive {row.identifier} runner does not route through its feature selection source",
            )
            require(
                row.identifier in selection_path.read_text(encoding="utf-8"),
                f"feature archive {row.identifier} feature selection source does not select its Cargo feature",
            )
        if row.state == "verified":
            verified_count += 1
            assert row.evidence_record is not None and row.dispatch_command is not None
            record = verified_records.get(row.evidence_record)
            require(record is not None, f"feature archive {row.identifier} names unknown verified evidence record")
            evidence = record.get("native_evidence")
            require(isinstance(evidence, list), f"feature archive {row.identifier} evidence record has no native evidence")
            expected_command = f"./scripts/dev-x86_64.sh {row.dispatch_command}"
            require(
                any(isinstance(item, Mapping) and item.get("command") == expected_command for item in evidence),
                f"feature archive {row.identifier} evidence record does not run {row.dispatch_command}",
            )
            require(
                row.dispatch_command in dispatcher,
                f"feature archive {row.identifier} dispatch command is not registered",
            )
        else:
            planned_count += 1
            require(row.evidence_record is None and row.dispatch_command is None, f"planned feature archive {row.identifier} claims verified evidence")

        for name in row.additive_callables:
            require(
                name not in static_export_set,
                f"feature archive {row.identifier} additive callable {name} is already default-static",
            )
            previous = additive_owners.setdefault(name, row.identifier)
            require(previous == row.identifier, f"feature archive callable {name} has multiple owners")
        baseline = selected_baseline_callables(row, rows, static_export_set)
        for name in row.replacement_callables:
            require(
                name in baseline,
                f"feature archive {row.identifier} replacement callable {name} is not in its selected baseline",
            )
        for alias in row.aliases:
            previous = alias_owners.setdefault(alias.name, row.identifier)
            require(previous == row.identifier, f"feature archive alias {alias.name} has multiple owners")
    return {
        "feature_archive_count": len(rows),
        "planned_feature_archive_count": planned_count,
        "verified_feature_archive_count": verified_count,
    }


def partition_candidate_callables(
    rows: Sequence[FeatureArchive],
    *,
    candidate_callables: Iterable[str],
    static_exports: Iterable[str],
) -> CallableProviderPartition:
    """Partition header-declared external functions without treating plans as proof."""

    candidates = set(candidate_callables)
    static_export_set = set(static_exports)
    require(candidates, "candidate callable set is empty")
    validate_abi_only_callable_ownership(
        rows,
        static_exports=static_export_set,
        candidate_callables=candidates,
    )
    default_static = tuple(sorted(candidates & static_export_set))
    owned: set[str] = set(default_static)
    verified: list[tuple[FeatureArchive, tuple[str, ...]]] = []
    planned: list[tuple[FeatureArchive, tuple[str, ...]]] = []
    replacements: list[tuple[FeatureArchive, tuple[str, ...]]] = []
    for row in rows:
        additions = tuple(row.additive_callables)
        for name in additions:
            require(name in candidates, f"feature archive {row.identifier} additive callable {name} is not header-declared")
            require(name not in owned, f"feature archive callable {name} is not exclusively owned")
            owned.add(name)
        replacement_members = tuple(row.replacement_callables)
        baseline = selected_baseline_callables(row, rows, static_export_set)
        for name in replacement_members:
            require(name in candidates, f"feature archive {row.identifier} replacement callable {name} is not header-declared")
            require(name in baseline, f"feature archive {row.identifier} replacement callable {name} is not in its selected baseline")
        for alias in row.aliases:
            if alias.name in candidates:
                require(
                    alias.name in additions or alias.name in replacement_members,
                    f"feature archive {row.identifier} header alias {alias.name} has no callable ownership",
                )
        if row.state == "verified":
            verified.append((row, additions))
        else:
            planned.append((row, additions))
        if replacement_members:
            replacements.append((row, replacement_members))
    unprovided = tuple(sorted(candidates - owned))
    partition = CallableProviderPartition(
        default_static=default_static,
        verified_feature_archives=tuple(verified),
        declared_unverified_feature_archives=tuple(planned),
        unprovided=unprovided,
        replacement_variants=tuple(replacements),
    )
    require(
        sum(partition.counts().values()) == len(candidates),
        "callable provider partition is not exhaustive",
    )
    return partition
