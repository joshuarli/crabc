#!/usr/bin/env python3
"""Strict policy for reviewed native callable extensions in matched headers.

A project-only header can be accounted as a whole path.  A native C ABI
extension such as ``tgkill`` instead lives in a header that pinned musl also
ships, so each compiler-derived matrix must retain the raw candidate-only fact
while applying this one exact reviewed disposition.  This module deliberately
has no wildcard or family rule: every name, physical declaring header,
signature, profile, direct-include root, and selected provider route is part of
the finite contract.  Evidence entries are canonical repository-relative
identifiers here; the named native component owns validation of the referenced
source, header, and source-sealed runtime evidence.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "header_callable_extension_contract.toml"
SCHEMA = "crabc.x86_64-header-callable-extension-contract/v1"
TARGET = "x86_64-unknown-linux-musl"
PLATFORM = "Linux/x86-64 little-endian"
ORACLE = "Pinned musl 1.2.6"
PROFILES = (
    "c11-gnu",
    "cxx17-gnu",
    "c11-strict",
    "c11-posix-2008",
    "c11-xopen-700",
    "c11-bsd",
    "cxx17-strict",
)
VISIBLE_PROFILES = ("c11-gnu", "cxx17-gnu", "c11-bsd", "cxx17-strict")
HIDDEN_PROFILES = ("c11-strict", "c11-posix-2008", "c11-xopen-700")
VISIBLE_FROM_HEADERS = (
    "aio.h",
    "signal.h",
    "sys/signal.h",
    "sys/ucontext.h",
    "sys/wait.h",
    "ucontext.h",
    "wait.h",
)
REVIEWED_COMPARISON = "candidate-only-reviewed-native-callable-extension"
REVIEWED_DISPOSITION = "retained-reviewed-native-c-abi-callable-extension"
PROVIDER_ROUTE = "default-static"
EXPECTED_RECORDS = (("signal.h", "tgkill"),)
EXPECTED_COMPONENT_CONTRACT = "compat/x86_64/native_thread_signal_abi.json"
EXPECTED_EVIDENCE = (
    "include/signal.h",
    "libc/src/c_abi/x86_64/thread_signal.rs",
    "compat/x86_64/native-thread-signal-abi.md",
)
POLICY = {
    "candidate_declaration_must_be_physical": True,
    "direct_include_roots_exact": True,
    "exact_name_header_signature": True,
    "family_promotion": False,
    "hidden_profiles_absent": True,
    "provider_route_checked_separately": True,
    "public_support": False,
    "raw_candidate_only_differences_retained": True,
    "reference_declaration_absent": True,
    "visible_profiles_exact": True,
}


class CallableExtensionContractError(ValueError):
    """The finite native callable-extension policy cannot be trusted."""


@dataclass(frozen=True)
class CallableExtension:
    """One exact reviewed candidate-only function in a matched public header."""

    header: str
    name: str
    declaration_kind: str
    classification: str
    signature: str
    c_linkage_symbol: str
    visible_profiles: tuple[str, ...]
    hidden_profiles: tuple[str, ...]
    visible_from_headers: tuple[str, ...]
    provider_route: str
    disposition: str
    component_contract: str
    evidence: tuple[str, ...]

    def abi_signature_for(self, profile: str) -> str:
        require(profile in PROFILES, f"unknown extension profile: {profile}")
        return f"{self.signature}|mangled={self.c_linkage_symbol}"

    def is_visible_in_row(self, header: str, profile: str) -> bool:
        return profile in self.visible_profiles and header in self.visible_from_headers

    def as_report(self) -> dict[str, Any]:
        return {
            "c_linkage_symbol": self.c_linkage_symbol,
            "classification": self.classification,
            "component_contract": self.component_contract,
            "declaration_kind": self.declaration_kind,
            "disposition": self.disposition,
            "evidence": list(self.evidence),
            "header": self.header,
            "hidden_profiles": list(self.hidden_profiles),
            "name": self.name,
            "provider_route": self.provider_route,
            "signature": self.signature,
            "visible_from_headers": list(self.visible_from_headers),
            "visible_profiles": list(self.visible_profiles),
        }


@dataclass(frozen=True)
class CallableExtensionContract:
    """The closed set of reviewed native callable extension records."""

    profiles: tuple[str, ...]
    extensions: tuple[CallableExtension, ...]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CallableExtensionContractError(message)


def string_tuple(value: object, location: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    require(isinstance(value, list), f"{location} must be an array")
    result: list[str] = []
    for index, item in enumerate(value):
        require(isinstance(item, str) and item, f"{location}[{index}] must be a nonempty string")
        result.append(item)
    require(allow_empty or bool(result), f"{location} must not be empty")
    require(len(result) == len(set(result)), f"{location} contains duplicates")
    return tuple(result)


def repository_relative_path(value: object, location: str) -> str:
    require(isinstance(value, str) and value, f"{location} must be a nonempty repository path")
    path = Path(value)
    require(not path.is_absolute() and ".." not in path.parts and "\\" not in value, f"{location} escapes the repository")
    canonical = path.as_posix()
    require(value == canonical and canonical != ".", f"{location} must use a canonical repository path")
    return canonical


def exact_boolean_policy(value: object) -> dict[str, bool]:
    """Accept only the fixed policy's exact Boolean values.

    TOML permits integers, and Python considers ``0 == False`` and
    ``1 == True``.  Policy bits are contract values rather than truthy
    convenience inputs, so preserve their type as well as their value.
    """

    require(isinstance(value, Mapping), "callable extension policy must be a table")
    require(set(value) == set(POLICY), "callable extension policy keys changed")
    result: dict[str, bool] = {}
    for key, expected in POLICY.items():
        actual = value[key]
        require(type(actual) is bool and actual is expected, f"callable extension policy.{key} changed")
        result[key] = actual
    return result


def load_extension(value: object, index: int) -> CallableExtension:
    location = f"reviewed_callable_extension[{index}]"
    require(isinstance(value, Mapping), f"{location} must be a table")
    expected_keys = {
        "header",
        "name",
        "declaration_kind",
        "classification",
        "signature",
        "c_linkage_symbol",
        "visible_profiles",
        "hidden_profiles",
        "visible_from_headers",
        "provider_route",
        "disposition",
        "component_contract",
        "evidence",
    }
    require(set(value) == expected_keys, f"{location} keys changed")
    header = value["header"]
    name = value["name"]
    require(isinstance(header, str) and header, f"{location}.header is invalid")
    require(isinstance(name, str) and name, f"{location}.name is invalid")
    require((header, name) in EXPECTED_RECORDS, f"{location} is not an approved exact native extension")
    declaration_kind = value["declaration_kind"]
    classification = value["classification"]
    signature = value["signature"]
    c_linkage_symbol = value["c_linkage_symbol"]
    require(declaration_kind == "function", f"{location}.declaration_kind must remain function")
    require(classification == "external", f"{location}.classification must remain external")
    require(signature == "int (int, int, int)", f"{location}.signature changed")
    require(c_linkage_symbol == name, f"{location}.c_linkage_symbol must retain C spelling")
    visible_profiles = string_tuple(value["visible_profiles"], f"{location}.visible_profiles")
    hidden_profiles = string_tuple(value["hidden_profiles"], f"{location}.hidden_profiles")
    require(visible_profiles == VISIBLE_PROFILES, f"{location}.visible_profiles changed")
    require(hidden_profiles == HIDDEN_PROFILES, f"{location}.hidden_profiles changed")
    require(
        tuple(profile for profile in PROFILES if profile in visible_profiles or profile in hidden_profiles) == PROFILES,
        f"{location} does not partition the fixed compiler profiles",
    )
    require(not set(visible_profiles) & set(hidden_profiles), f"{location} profile classes overlap")
    visible_from_headers = string_tuple(value["visible_from_headers"], f"{location}.visible_from_headers")
    require(visible_from_headers == VISIBLE_FROM_HEADERS, f"{location}.visible_from_headers changed")
    provider_route = value["provider_route"]
    disposition = value["disposition"]
    require(provider_route == PROVIDER_ROUTE, f"{location}.provider_route changed")
    require(disposition == REVIEWED_DISPOSITION, f"{location}.disposition changed")
    component_contract = repository_relative_path(value["component_contract"], f"{location}.component_contract")
    require(component_contract == EXPECTED_COMPONENT_CONTRACT, f"{location}.component_contract changed")
    evidence = tuple(repository_relative_path(item, f"{location}.evidence[{item_index}]") for item_index, item in enumerate(string_tuple(value["evidence"], f"{location}.evidence")))
    require(evidence == EXPECTED_EVIDENCE, f"{location}.evidence source mapping changed")
    return CallableExtension(
        header=header,
        name=name,
        declaration_kind=declaration_kind,
        classification=classification,
        signature=signature,
        c_linkage_symbol=c_linkage_symbol,
        visible_profiles=visible_profiles,
        hidden_profiles=hidden_profiles,
        visible_from_headers=visible_from_headers,
        provider_route=provider_route,
        disposition=disposition,
        component_contract=component_contract,
        evidence=evidence,
    )


def load_contract(path: Path = CONTRACT_PATH) -> CallableExtensionContract:
    """Load only the single finite reviewed exception record."""

    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CallableExtensionContractError(f"cannot load {path}: {error}") from error
    require(isinstance(raw, Mapping), "callable extension contract must be a table")
    expected_keys = {
        "schema",
        "target",
        "platform",
        "oracle",
        "profiles",
        "policy",
        "reviewed_callable_extension",
    }
    require(set(raw) == expected_keys, "callable extension contract keys changed")
    require(raw["schema"] == SCHEMA, "callable extension contract schema changed")
    require(raw["target"] == TARGET, "callable extension target changed")
    require(raw["platform"] == PLATFORM, "callable extension platform changed")
    require(raw["oracle"] == ORACLE, "callable extension oracle changed")
    profiles = string_tuple(raw["profiles"], "profiles")
    require(profiles == PROFILES, "callable extension profile order changed")
    require(exact_boolean_policy(raw["policy"]) == POLICY, "callable extension policy changed")
    values = raw["reviewed_callable_extension"]
    require(isinstance(values, list) and values, "reviewed callable extension rows are missing")
    extensions = tuple(load_extension(value, index) for index, value in enumerate(values))
    require(
        tuple((extension.header, extension.name) for extension in extensions) == EXPECTED_RECORDS,
        "reviewed callable extension roster changed",
    )
    return CallableExtensionContract(profiles=profiles, extensions=extensions)


def extension_for_row(
    contract: CallableExtensionContract,
    *,
    header: str,
    profile: str,
) -> CallableExtension | None:
    """Return the one review record allowed to differ in a direct include row."""

    require(profile in contract.profiles, f"unknown extension profile: {profile}")
    matches = [extension for extension in contract.extensions if extension.is_visible_in_row(header, profile)]
    require(len(matches) <= 1, f"multiple reviewed extensions overlap {header}:{profile}")
    return matches[0] if matches else None


def named_records(records: Sequence[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    for index, record in enumerate(records):
        require(isinstance(record, Mapping), f"extension record[{index}] is invalid")
        if record.get("name") == name:
            result.append(record)
    return result


def validate_callable_inventory_records(
    contract: CallableExtensionContract,
    records: Sequence[Mapping[str, Any]],
    *,
    known_headers: frozenset[str],
) -> frozenset[tuple[str, str]]:
    """Require physical candidate records and zero pinned declarations.

    The callable inventory merges a physical declaration across all direct
    include roots.  The returned rows are the exact raw candidate-only rows
    that the callable-visibility matrix may classify as reviewed; no caller
    receives a suppression token for any other name or row.
    """

    expected_rows: set[tuple[str, str]] = set()
    for extension in contract.extensions:
        require(
            set(extension.visible_from_headers) <= known_headers,
            f"extension {extension.header}:{extension.name} has an unknown direct include root",
        )
        targets = named_records(records, extension.name)
        references = [record for record in targets if record.get("tree") == "reference"]
        require(
            not references,
            f"extension {extension.header}:{extension.name} reference declares the reviewed native callable",
        )
        unknown_trees = [record for record in targets if record.get("tree") != "candidate"]
        require(
            not unknown_trees,
            f"extension {extension.header}:{extension.name} has a noncandidate inventory record",
        )
        candidate_by_profile: dict[str, Mapping[str, Any]] = {}
        for record in targets:
            profile = record.get("profile")
            require(isinstance(profile, str) and profile in contract.profiles, f"extension {extension.name} profile is invalid")
            require(profile in extension.visible_profiles, f"extension {extension.name} appears in hidden profile {profile}")
            require(profile not in candidate_by_profile, f"extension {extension.name} has duplicate candidate profile {profile}")
            candidate_by_profile[profile] = record
            require(record.get("classification") == extension.classification, f"extension {extension.name} classification changed")
            require(record.get("declaration_kind") == extension.declaration_kind, f"extension {extension.name} declaration kind changed")
            require(record.get("declaring_header") == extension.header, f"extension {extension.name} declaring header changed")
            require(record.get("origin_resolution") == "physical", f"extension {extension.name} must retain physical declaration provenance")
            require(record.get("storage_class") == "extern", f"extension {extension.name} storage class changed")
            require(record.get("type") == extension.signature, f"extension {extension.name} signature changed")
            roots = record.get("visible_from_headers")
            require(isinstance(roots, list), f"extension {extension.name} direct include roots are invalid")
            require(tuple(roots) == extension.visible_from_headers, f"extension {extension.name} direct include roots changed")
        missing = set(extension.visible_profiles) - set(candidate_by_profile)
        require(not missing, f"extension {extension.name} missing candidate profile(s): {sorted(missing)}")
        require(
            set(candidate_by_profile) == set(extension.visible_profiles),
            f"extension {extension.name} candidate profile coverage changed",
        )
        expected_rows.update(
            (header, profile)
            for profile in extension.visible_profiles
            for header in extension.visible_from_headers
        )
    return frozenset(expected_rows)


def callable_units(value: Sequence[Mapping[str, Any]], location: str) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        require(isinstance(item, Mapping), f"{location}[{index}] is invalid")
        classification = item.get("classification")
        name = item.get("name")
        require(isinstance(classification, str) and classification, f"{location}[{index}].classification is invalid")
        require(isinstance(name, str) and name, f"{location}[{index}].name is invalid")
        unit = (classification, name)
        require(unit not in result, f"{location} contains duplicate callable units")
        result.add(unit)
    return result


def review_callable_difference(
    contract: CallableExtensionContract,
    *,
    header: str,
    profile: str,
    candidate_only: Sequence[Mapping[str, Any]],
    reference_only: Sequence[Mapping[str, Any]],
) -> CallableExtension | None:
    """Accept only the exact raw callable difference selected by this policy."""

    candidate = callable_units(candidate_only, f"candidate-only {header}:{profile}")
    reference = callable_units(reference_only, f"reference-only {header}:{profile}")
    reviewed = extension_for_row(contract, header=header, profile=profile)
    for extension in contract.extensions:
        target_names = {
            name
            for _classification, name in candidate | reference
            if name == extension.name
        }
        if reviewed is extension:
            expected = {(extension.classification, extension.name)}
            require(target_names == {extension.name}, f"extension {extension.name} is missing from reviewed row {header}:{profile}")
            require(candidate == expected, f"extension {extension.name} reviewed row has additional raw candidate-only callable differences")
            require(not reference, f"extension {extension.name} reviewed row has additional raw reference-only callable differences")
            return extension
        if target_names:
            if profile in extension.hidden_profiles:
                raise CallableExtensionContractError(
                    f"extension {extension.name} appears in hidden profile {profile} through {header}"
                )
            raise CallableExtensionContractError(
                f"extension {extension.name} appears outside its reviewed direct include roots: {header}:{profile}"
            )
    return None


def declaration_facts(value: object, location: str) -> list[Mapping[str, Any]]:
    require(isinstance(value, list), f"{location} must be an array")
    result: list[Mapping[str, Any]] = []
    for index, item in enumerate(value):
        require(isinstance(item, Mapping), f"{location}[{index}] is invalid")
        kind = item.get("kind")
        name = item.get("name")
        signature = item.get("signature")
        require(isinstance(kind, str) and kind, f"{location}[{index}].kind is invalid")
        require(isinstance(name, str) and name, f"{location}[{index}].name is invalid")
        require(isinstance(signature, str) and signature, f"{location}[{index}].signature is invalid")
        result.append(item)
    return result


def review_declaration_difference(
    contract: CallableExtensionContract,
    *,
    header: str,
    profile: str,
    difference: Mapping[str, Any],
) -> CallableExtension | None:
    """Accept the target only with its exact C ABI spelling and C linkage."""

    require(isinstance(difference, Mapping), f"declaration difference is invalid: {header}:{profile}")
    require(
        set(difference) >= {"candidate_only", "reference_only", "incompatible"},
        f"declaration difference fields are invalid: {header}:{profile}",
    )
    candidate = declaration_facts(difference["candidate_only"], f"candidate-only declaration {header}:{profile}")
    reference = declaration_facts(difference["reference_only"], f"reference-only declaration {header}:{profile}")
    raw_incompatible = difference["incompatible"]
    require(isinstance(raw_incompatible, list), f"incompatible declaration {header}:{profile} must be an array")
    incompatible: list[Mapping[str, Any]] = []
    for index, item in enumerate(raw_incompatible):
        require(isinstance(item, Mapping), f"incompatible declaration {header}:{profile}[{index}] is invalid")
        name = item.get("name")
        require(isinstance(name, str) and name, f"incompatible declaration {header}:{profile}[{index}].name is invalid")
        incompatible.append(item)
    reviewed = extension_for_row(contract, header=header, profile=profile)
    for extension in contract.extensions:
        candidate_target = [fact for fact in candidate if fact.get("name") == extension.name]
        reference_target = [fact for fact in reference if fact.get("name") == extension.name]
        incompatible_target = [fact for fact in incompatible if fact.get("name") == extension.name]
        if reviewed is extension:
            require(not reference_target and not incompatible_target, f"extension {extension.name} reviewed row has a reference declaration")
            require(len(candidate_target) == 1, f"extension {extension.name} reviewed row is missing its candidate declaration")
            target = candidate_target[0]
            require(target.get("kind") == extension.declaration_kind, f"extension {extension.name} declaration kind changed")
            require(target.get("signature") == extension.abi_signature_for(profile), f"extension {extension.name} signature or C linkage changed")
            require(len(candidate) == 1 and not reference and not incompatible, f"extension {extension.name} reviewed row has additional raw declaration differences")
            return extension
        if candidate_target or reference_target or incompatible_target:
            if profile in extension.hidden_profiles:
                raise CallableExtensionContractError(
                    f"extension {extension.name} declaration appears in hidden profile {profile} through {header}"
                )
            raise CallableExtensionContractError(
                f"extension {extension.name} declaration appears outside its reviewed direct include roots: {header}:{profile}"
            )
    return None


def validate_provider_routes(
    contract: CallableExtensionContract,
    *,
    candidate_external: Sequence[str],
    static_exports: Sequence[str],
    default_static: Sequence[str],
) -> list[dict[str, Any]]:
    """Check selected archive routing without relabeling declaration semantics."""

    candidate_set = set(candidate_external)
    static_export_set = set(static_exports)
    default_static_set = set(default_static)
    require(len(candidate_set) == len(candidate_external), "candidate external provider names contain duplicates")
    require(len(static_export_set) == len(static_exports), "static export provider names contain duplicates")
    require(len(default_static_set) == len(default_static), "default static provider names contain duplicates")
    records: list[dict[str, Any]] = []
    for extension in contract.extensions:
        require(extension.name in candidate_set, f"extension {extension.name} is absent from candidate external provider routing")
        require(extension.provider_route == PROVIDER_ROUTE, f"extension {extension.name} provider route is unsupported")
        require(extension.name in static_export_set, f"extension {extension.name} is absent from default static exports")
        require(extension.name in default_static_set, f"extension {extension.name} is absent from default static provider routing")
        records.append(
            {
                "candidate_external_present": True,
                "header": extension.header,
                "name": extension.name,
                "provider_route": extension.provider_route,
            }
        )
    return records
