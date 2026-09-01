#!/usr/bin/env python3
"""Generate the finite x86 public-header callable feature-visibility matrix.

The checked callable inventory is already compiler-derived for every direct
public include/profile pair.  This layer turns that inventory into a stable,
reviewable comparison of *consumer-visible callable names and classes* between
the project headers and pinned musl 1.2.6.  It deliberately does not compare
prototypes, macro replacements, non-callable declarations, layouts, archive
linkage, or runtime behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "header_callable_visibility_matrix.toml"
INVENTORY_SCHEMA = "crabc.x86_64-header-callable-inventory-report/v2"
SCHEMA = "crabc.x86_64-header-callable-feature-visibility-matrix-report/v1"
CONTRACT_SCHEMA = "crabc.x86_64-header-callable-feature-visibility-matrix/v1"
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
CALLABLE_CLASSIFICATIONS = frozenset({"external", "inline", "macro"})
POLICY = {
    "compiler_derived_inventory": True,
    "direct_public_include_visibility": True,
    "callable_names_and_classes_only": True,
    "header_text_parsing": False,
    "prototype_or_macro_replacement_equality": False,
    "noncallable_abi": False,
    "linkage_or_runtime": False,
    "family_promotion": False,
    "public_support": False,
}
PROJECT_ONLY_PATHS = (
    "daemon.h",
    "dn_expand.h",
    "linux/capability.h",
    "lrand48.h",
    "pthread_atfork.h",
    "stdatomic.h",
    "strverscmp.h",
    "sys/module.h",
)


class MatrixError(ValueError):
    """The finite feature-visibility evidence cannot be evaluated safely."""


@dataclass(frozen=True)
class ProjectOnlyHeader:
    """Current, non-promoting disposition of one project-only public path."""

    path: str
    disposition: str
    origin: str = ""
    observed_profiles: tuple[str, ...] = ()
    retained_profiles: tuple[str, ...] = ()
    c_surface: str = ""
    cxx_surface: str = ""
    cxx_linkage: str = ""
    canonical_headers: tuple[str, ...] = ()
    canonical_visibility: str = ""
    declared_symbols: tuple[str, ...] = ()
    capability_owner: str = ""
    x86_family: str = ""
    provider_state: str = ""
    evidence: tuple[str, ...] = ()
    removal_requires_abi_decision: bool = True

    def as_report(self) -> dict[str, Any]:
        return {
            "c_surface": self.c_surface,
            "canonical_headers": list(self.canonical_headers),
            "canonical_visibility": self.canonical_visibility,
            "capability_owner": self.capability_owner,
            "cxx_linkage": self.cxx_linkage,
            "cxx_surface": self.cxx_surface,
            "declared_symbols": list(self.declared_symbols),
            "disposition": self.disposition,
            "evidence": list(self.evidence),
            "observed_profiles": list(self.observed_profiles),
            "origin": self.origin,
            "path": self.path,
            "provider_state": self.provider_state,
            "removal_requires_abi_decision": self.removal_requires_abi_decision,
            "retained_profiles": list(self.retained_profiles),
            "x86_family": self.x86_family,
        }


@dataclass(frozen=True)
class MatrixContract:
    """Trusted finite inputs for an all-header callable comparison."""

    inventory: Path
    public_headers: Path
    generated_report: Path
    profiles: tuple[str, ...]
    oracle_not_applicable: Mapping[tuple[str, str], str]
    project_only_headers: tuple[ProjectOnlyHeader, ...]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MatrixError(message)


def relative_project_path(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty path")
    path = Path(value)
    require(not path.is_absolute() and ".." not in path.parts, f"{location} escapes the repository")
    result = ROOT / path
    require(result.is_file() and not result.is_symlink(), f"{location} is not a regular repository file: {value}")
    return result


def relative_project_destination(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty path")
    path = Path(value)
    require(not path.is_absolute() and ".." not in path.parts, f"{location} escapes the repository")
    parent = ROOT / path.parent
    require(parent.is_dir() and not parent.is_symlink(), f"{location} parent is unsafe: {path.parent}")
    return ROOT / path


def string_tuple(value: object, location: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    require(isinstance(value, list), f"{location} must be an array")
    result: list[str] = []
    for index, item in enumerate(value):
        require(isinstance(item, str) and item, f"{location}[{index}] must be a nonempty string")
        result.append(item)
    require(allow_empty or bool(result), f"{location} must not be empty")
    require(len(result) == len(set(result)), f"{location} contains duplicates")
    return tuple(result)


def load_project_only_header(value: object, index: int) -> ProjectOnlyHeader:
    location = f"project_only_header[{index}]"
    require(isinstance(value, Mapping), f"{location} must be a table")
    expected_keys = {
        "path",
        "disposition",
        "origin",
        "observed_profiles",
        "retained_profiles",
        "c_surface",
        "cxx_surface",
        "cxx_linkage",
        "canonical_headers",
        "canonical_visibility",
        "declared_symbols",
        "capability_owner",
        "x86_family",
        "provider_state",
        "evidence",
        "removal_requires_abi_decision",
    }
    require(set(value) == expected_keys, f"{location} keys changed")
    path = value["path"]
    disposition = value["disposition"]
    require(isinstance(path, str) and path in PROJECT_ONLY_PATHS, f"{location}.path is invalid")
    require(
        disposition == "retained-pending-c-abi-policy",
        f"{location}.disposition must retain the pending C ABI policy boundary",
    )
    origin = value["origin"]
    require(origin in {"standalone-alias", "project-extension", "linux-uapi-local", "c11-vocabulary"}, f"{location}.origin is invalid")
    observed_profiles = string_tuple(value["observed_profiles"], f"{location}.observed_profiles")
    retained_profiles = string_tuple(value["retained_profiles"], f"{location}.retained_profiles")
    require(observed_profiles == PROFILES, f"{location}.observed_profiles drifted")
    require(retained_profiles == PROFILES, f"{location}.retained_profiles drifted")
    c_surface = value["c_surface"]
    cxx_surface = value["cxx_surface"]
    cxx_linkage = value["cxx_linkage"]
    require(c_surface in {"callable-declarations", "callable-types-and-macros"}, f"{location}.c_surface is invalid")
    require(
        cxx_surface in {"callable-declarations", "callable-types-and-macros", "empty-intentional"},
        f"{location}.cxx_surface is invalid",
    )
    require(cxx_linkage in {"extern-c", "cxx-default", "no-callable-surface"}, f"{location}.cxx_linkage is invalid")
    if cxx_surface == "empty-intentional":
        require(cxx_linkage == "no-callable-surface", f"{location} empty C++ surface has linkage")
    else:
        require(cxx_linkage != "no-callable-surface", f"{location} callable C++ surface lacks linkage")
    canonical_headers = string_tuple(value["canonical_headers"], f"{location}.canonical_headers", allow_empty=True)
    canonical_visibility = value["canonical_visibility"]
    require(isinstance(canonical_visibility, str) and canonical_visibility, f"{location}.canonical_visibility is invalid")
    declared_symbols = string_tuple(value["declared_symbols"], f"{location}.declared_symbols")
    require(declared_symbols == tuple(sorted(declared_symbols)), f"{location}.declared_symbols must be ASCII sorted")
    capability_owner = value["capability_owner"]
    x86_family = value["x86_family"]
    provider_state = value["provider_state"]
    require(isinstance(capability_owner, str) and capability_owner, f"{location}.capability_owner is invalid")
    require(isinstance(x86_family, str) and x86_family, f"{location}.x86_family is invalid")
    require(provider_state in {"default-static", "unprovided"}, f"{location}.provider_state is invalid")
    evidence = string_tuple(value["evidence"], f"{location}.evidence")
    require(
        value["removal_requires_abi_decision"] is True,
        f"{location}.removal_requires_abi_decision must remain true",
    )
    return ProjectOnlyHeader(
        path=path,
        disposition=disposition,
        origin=origin,
        observed_profiles=observed_profiles,
        retained_profiles=retained_profiles,
        c_surface=c_surface,
        cxx_surface=cxx_surface,
        cxx_linkage=cxx_linkage,
        canonical_headers=canonical_headers,
        canonical_visibility=canonical_visibility,
        declared_symbols=declared_symbols,
        capability_owner=capability_owner,
        x86_family=x86_family,
        provider_state=provider_state,
        evidence=evidence,
        removal_requires_abi_decision=True,
    )


def load_contract(path: Path = CONTRACT_PATH) -> MatrixContract:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise MatrixError(f"cannot load {path.relative_to(ROOT)}: {error}") from error

    expected_keys = {
        "schema",
        "target",
        "platform",
        "oracle",
        "inventory",
        "public_headers",
        "generated_report",
        "pinned_public_header_count",
        "candidate_public_header_count",
        "policy",
        "profiles",
        "oracle_not_applicable",
        "project_only_header",
    }
    require(set(raw) == expected_keys, "callable visibility matrix contract keys changed")
    require(raw["schema"] == CONTRACT_SCHEMA, "callable visibility matrix contract schema changed")
    require(raw["target"] == TARGET, "callable visibility matrix contract target changed")
    require(raw["platform"] == PLATFORM, "callable visibility matrix contract platform changed")
    require(raw["oracle"] == ORACLE, "callable visibility matrix contract oracle changed")
    require(raw["policy"] == POLICY, "callable visibility matrix policy changed")
    profiles = string_tuple(raw["profiles"], "profiles")
    require(profiles == PROFILES, "callable visibility matrix profile order changed")
    require(raw["pinned_public_header_count"] == 183, "callable visibility matrix pinned header count changed")
    require(raw["candidate_public_header_count"] == 191, "callable visibility matrix candidate header count changed")

    raw_na = raw["oracle_not_applicable"]
    require(isinstance(raw_na, list), "oracle_not_applicable must be an array")
    oracle_not_applicable: dict[tuple[str, str], str] = {}
    for index, item in enumerate(raw_na):
        location = f"oracle_not_applicable[{index}]"
        require(isinstance(item, Mapping) and set(item) == {"header", "profile", "reason"}, f"{location} keys changed")
        header = item["header"]
        profile = item["profile"]
        reason = item["reason"]
        require(isinstance(header, str) and header, f"{location}.header is invalid")
        require(profile in PROFILES, f"{location}.profile is invalid")
        require(isinstance(reason, str) and reason, f"{location}.reason is invalid")
        key = (header, profile)
        require(key not in oracle_not_applicable, f"{location} duplicates {header}:{profile}")
        oracle_not_applicable[key] = reason
    require(
        tuple(oracle_not_applicable) == (("aio.h", "c11-strict"),),
        "callable visibility matrix oracle exception roster changed",
    )

    raw_project_only = raw["project_only_header"]
    require(isinstance(raw_project_only, list), "project_only_header must be an array")
    project_only_headers = tuple(load_project_only_header(item, index) for index, item in enumerate(raw_project_only))
    require(
        tuple(header.path for header in project_only_headers) == PROJECT_ONLY_PATHS,
        "project-only header disposition roster changed",
    )
    return MatrixContract(
        inventory=relative_project_path(raw["inventory"], "inventory"),
        public_headers=relative_project_path(raw["public_headers"], "public_headers"),
        generated_report=relative_project_destination(raw["generated_report"], "generated_report"),
        profiles=profiles,
        oracle_not_applicable=oracle_not_applicable,
        project_only_headers=project_only_headers,
    )


def load_headers(path: Path) -> tuple[str, ...]:
    try:
        values = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise MatrixError(f"cannot read public header inventory: {error}") from error
    require(values and all(value and not value.startswith("#") for value in values), "public header inventory is invalid")
    require(values == sorted(values), "public header inventory is not ASCII sorted")
    require(len(values) == len(set(values)) == 183, "public header inventory count changed")
    for value in values:
        relative = Path(value)
        require(not relative.is_absolute() and ".." not in relative.parts and value == relative.as_posix(), f"public header inventory path is unsafe: {value}")
    return tuple(values)


def load_inventory(path: Path) -> Mapping[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MatrixError(f"cannot load callable inventory: {error}") from error
    require(isinstance(raw, Mapping), "callable inventory root is invalid")
    return raw


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def index_profile_runs(inventory: Mapping[str, Any]) -> dict[tuple[str, str, str], str]:
    raw_runs = inventory.get("profile_runs")
    require(isinstance(raw_runs, list), "callable inventory profile_runs are missing")
    result: dict[tuple[str, str, str], str] = {}
    for index, item in enumerate(raw_runs):
        location = f"inventory.profile_runs[{index}]"
        require(isinstance(item, Mapping), f"{location} is invalid")
        tree = item.get("tree")
        header = item.get("header")
        profile = item.get("profile")
        status = item.get("status")
        require(tree in {"candidate", "reference"}, f"{location}.tree is invalid")
        require(isinstance(header, str) and header, f"{location}.header is invalid")
        require(profile in PROFILES, f"{location}.profile is invalid")
        require(isinstance(status, str) and status, f"{location}.status is invalid")
        key = (tree, profile, header)
        require(key not in result, f"{location} duplicates profile run {tree}:{profile}:{header}")
        result[key] = status
    return result


def direct_callable_units(
    inventory: Mapping[str, Any],
    *,
    known_headers: frozenset[str],
) -> dict[tuple[str, str, str], frozenset[tuple[str, str]]]:
    raw_callables = inventory.get("callables")
    require(isinstance(raw_callables, list), "callable inventory callables are missing")
    result: dict[tuple[str, str, str], set[tuple[str, str]]] = defaultdict(set)
    for index, item in enumerate(raw_callables):
        location = f"inventory.callables[{index}]"
        require(isinstance(item, Mapping), f"{location} is invalid")
        tree = item.get("tree")
        classification = item.get("classification")
        if tree not in {"candidate", "reference"} or classification not in CALLABLE_CLASSIFICATIONS:
            # The inventory's comparison/missing records intentionally do not
            # replace a direct compiler-observed header surface.
            continue
        profile = item.get("profile")
        name = item.get("name")
        headers = item.get("visible_from_headers")
        require(profile in PROFILES, f"{location}.profile is invalid")
        require(isinstance(name, str) and name, f"{location}.name is invalid")
        require(isinstance(headers, list) and headers, f"{location}.visible_from_headers is invalid")
        for header in headers:
            require(isinstance(header, str) and header in known_headers, f"{location} has an unknown direct public header")
            result[(tree, profile, header)].add((classification, name))
    return {key: frozenset(value) for key, value in result.items()}


def canonical_units(units: frozenset[tuple[str, str]]) -> list[dict[str, str]]:
    return [
        {"classification": classification, "name": name}
        for classification, name in sorted(units)
    ]


def validate_project_only_callable_surface(
    header: ProjectOnlyHeader,
    profile: str,
    candidate_units: frozenset[tuple[str, str]],
) -> None:
    """Bind retained project-only metadata to compiler-observed callables."""

    if profile.startswith("cxx17") and header.cxx_surface == "empty-intentional":
        require(
            not candidate_units,
            f"project-only {header.path}:{profile} intentionally-empty C++ surface exposes callables",
        )
        return

    observed_names = {name for _, name in candidate_units}
    missing = set(header.declared_symbols) - observed_names
    require(
        not missing,
        f"project-only {header.path}:{profile} declared symbols are absent from compiler-observed direct surface: {sorted(missing)}",
    )


def validate_inventory_profiles(inventory: Mapping[str, Any], contract: MatrixContract) -> None:
    require(inventory.get("schema") == INVENTORY_SCHEMA, "callable inventory schema changed")
    raw_profiles = inventory.get("profiles")
    require(isinstance(raw_profiles, list), "callable inventory profiles are missing")
    observed_profiles: list[str] = []
    for index, item in enumerate(raw_profiles):
        require(isinstance(item, Mapping), f"inventory.profiles[{index}] is invalid")
        identifier = item.get("id")
        require(isinstance(identifier, str), f"inventory.profiles[{index}].id is invalid")
        observed_profiles.append(identifier)
    require(tuple(observed_profiles) == contract.profiles, "callable inventory profile roster changed")


def build_report(
    *,
    contract: MatrixContract,
    inventory: Mapping[str, Any],
    pinned_headers: Sequence[str],
    candidate_headers: Sequence[str],
    input_digests: Mapping[str, str],
) -> dict[str, Any]:
    """Build a deterministic finite matrix from already compiler-derived data."""

    validate_inventory_profiles(inventory, contract)
    pinned = tuple(pinned_headers)
    candidate = tuple(candidate_headers)
    project_only = tuple(header.path for header in contract.project_only_headers)
    require(
        pinned == tuple(sorted(pinned)) and bool(pinned) and len(pinned) == len(set(pinned)),
        "pinned header roster is invalid",
    )
    require(candidate == tuple(sorted(candidate)) and len(candidate) == len(set(candidate)), "candidate header roster is invalid")
    require(set(candidate) == set(pinned) | set(project_only), "candidate roster is not pinned headers plus project-only paths")
    require(set(pinned).isdisjoint(project_only), "project-only paths overlap the pinned roster")
    require(len(candidate) == len(pinned) + len(project_only), "candidate header arithmetic changed")

    expected_digest_keys = {
        "callable_inventory_sha256",
        "matrix_contract_sha256",
        "public_header_inventory_sha256",
    }
    require(set(input_digests) == expected_digest_keys, "matrix input digest keys changed")
    require(all(isinstance(value, str) and value for value in input_digests.values()), "matrix input digest is empty")

    runs = index_profile_runs(inventory)
    expected_run_keys = {
        *( ("candidate", profile, header) for header in candidate for profile in contract.profiles ),
        *( ("reference", profile, header) for header in pinned for profile in contract.profiles ),
    }
    require(set(runs) == expected_run_keys, "callable inventory profile-run roster changed")
    for profile in contract.profiles:
        for header in candidate:
            require(runs[("candidate", profile, header)] == "ok", f"candidate compiler record is not ok: {header}:{profile}")
        for header in pinned:
            status = runs[("reference", profile, header)]
            if status == "oracle-not-applicable":
                require((header, profile) in contract.oracle_not_applicable, f"unexpected oracle-not-applicable row: {header}:{profile}")
            else:
                require(status == "ok", f"reference compiler record is not ok: {header}:{profile}")
    observed_oracle_not_applicable = {
        (header, profile)
        for header in pinned
        for profile in contract.profiles
        if runs[("reference", profile, header)] == "oracle-not-applicable"
    }
    require(
        observed_oracle_not_applicable == set(contract.oracle_not_applicable),
        "callable visibility matrix oracle exception roster is stale",
    )

    known_headers = frozenset(candidate)
    units = direct_callable_units(inventory, known_headers=known_headers)
    project_only_by_path = {header.path: header for header in contract.project_only_headers}
    rows: list[dict[str, Any]] = []
    comparison_counts: Counter[str] = Counter()
    matched_callable_count = 0
    candidate_only_callable_count = 0
    reference_only_callable_count = 0
    project_only_callable_count = 0
    oracle_not_applicable_candidate_visible_callable_count = 0

    for header in candidate:
        for profile in contract.profiles:
            candidate_units = units.get(("candidate", profile, header), frozenset())
            candidate_status = runs[("candidate", profile, header)]
            base: dict[str, Any] = {
                "candidate_callable_count": len(candidate_units),
                "candidate_status": candidate_status,
                "header": header,
                "profile": profile,
            }
            if header in project_only_by_path:
                validate_project_only_callable_surface(
                    project_only_by_path[header], profile, candidate_units
                )
                base.update(
                    {
                        "candidate_only": canonical_units(candidate_units),
                        "comparison": "candidate-only-retained-pending-c-abi-policy",
                        "matched_callable_count": 0,
                        "reference_callable_count": 0,
                        "reference_only": [],
                        "reference_status": "not-in-pinned-inventory",
                    }
                )
                project_only_callable_count += len(candidate_units)
            else:
                reference_status = runs[("reference", profile, header)]
                base["reference_status"] = reference_status
                if reference_status == "oracle-not-applicable":
                    base.update(
                        {
                            "candidate_only": [],
                            "candidate_visible": canonical_units(candidate_units),
                            "comparison": "oracle-not-applicable",
                            "matched_callable_count": 0,
                            "reference_callable_count": 0,
                            "reference_only": [],
                        }
                    )
                    oracle_not_applicable_candidate_visible_callable_count += len(candidate_units)
                else:
                    reference_units = units.get(("reference", profile, header), frozenset())
                    matched = candidate_units & reference_units
                    candidate_only = candidate_units - reference_units
                    reference_only = reference_units - candidate_units
                    comparison = "matched" if not candidate_only and not reference_only else "mismatch"
                    base.update(
                        {
                            "candidate_only": canonical_units(candidate_only),
                            "comparison": comparison,
                            "matched_callable_count": len(matched),
                            "reference_callable_count": len(reference_units),
                            "reference_only": canonical_units(reference_only),
                        }
                    )
                    matched_callable_count += len(matched)
                    candidate_only_callable_count += len(candidate_only)
                    reference_only_callable_count += len(reference_only)
            comparison_counts[str(base["comparison"])] += 1
            rows.append(base)

    mismatch_rows = comparison_counts["mismatch"]
    oracle_not_applicable_rows = comparison_counts["oracle-not-applicable"]
    project_only_rows = comparison_counts["candidate-only-retained-pending-c-abi-policy"]
    incomplete_reasons: list[str] = []
    if mismatch_rows:
        incomplete_reasons.append(f"{mismatch_rows} comparable pinned header/profile rows have callable visibility differences")
    if oracle_not_applicable_rows:
        incomplete_reasons.append(f"{oracle_not_applicable_rows} pinned-musl header/profile rows are oracle-not-applicable")
    if project_only_rows:
        incomplete_reasons.append(f"{project_only_rows} project-only header/profile rows remain pending C ABI policy")

    return {
        "schema": SCHEMA,
        "contract_schema": CONTRACT_SCHEMA,
        "target": TARGET,
        "platform": PLATFORM,
        "oracle": ORACLE,
        "inputs": dict(sorted(input_digests.items())),
        "scope": dict(POLICY),
        "profiles": list(contract.profiles),
        "project_only_headers": [header.as_report() for header in contract.project_only_headers],
        "rows": rows,
        "summary": {
            "candidate_only_callable_count": candidate_only_callable_count,
            "candidate_public_header_count": len(candidate),
            "comparable_row_count": comparison_counts["matched"] + mismatch_rows,
            "comparison_counts": dict(sorted(comparison_counts.items())),
            "complete": not incomplete_reasons,
            "incomplete_reasons": incomplete_reasons,
            "matched_callable_count": matched_callable_count,
            "mismatch_row_count": mismatch_rows,
            "oracle_not_applicable_row_count": oracle_not_applicable_rows,
            "oracle_not_applicable_candidate_visible_callable_count": (
                oracle_not_applicable_candidate_visible_callable_count
            ),
            "pinned_public_header_count": len(pinned),
            "pinned_row_count": len(pinned) * len(contract.profiles),
            "profile_count": len(contract.profiles),
            "project_only_callable_count": project_only_callable_count,
            "project_only_header_count": len(project_only),
            "project_only_row_count": project_only_rows,
            "reference_only_callable_count": reference_only_callable_count,
            "row_count": len(rows),
        },
    }


def build_file_report(contract: MatrixContract) -> dict[str, Any]:
    pinned_headers = load_headers(contract.public_headers)
    project_only = tuple(header.path for header in contract.project_only_headers)
    candidate_headers = tuple(sorted((*pinned_headers, *project_only)))
    return build_report(
        contract=contract,
        inventory=load_inventory(contract.inventory),
        pinned_headers=pinned_headers,
        candidate_headers=candidate_headers,
        input_digests={
            "callable_inventory_sha256": sha256_file(contract.inventory),
            "matrix_contract_sha256": sha256_file(CONTRACT_PATH),
            "public_header_inventory_sha256": sha256_file(contract.public_headers),
        },
    )


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def check_output(path: Path, rendered: str) -> None:
    try:
        existing = path.read_text(encoding="utf-8")
    except OSError as error:
        raise MatrixError(f"checked callable visibility matrix is missing: {path.relative_to(ROOT)} ({error})") from error
    require(existing == rendered, f"checked callable visibility matrix is stale: regenerate {path.relative_to(ROOT)} with --write")


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write a generated matrix to this exact path")
    parser.add_argument("--write", action="store_true", help="update the reviewed checked matrix")
    parser.add_argument("--check", action="store_true", help="require the checked matrix to match current inventory")
    parsed = parser.parse_args(arguments)
    require(not (parsed.write and parsed.check), "--write and --check cannot be combined")
    contract = load_contract()
    rendered = canonical_json(build_file_report(contract))
    if parsed.output is not None:
        require(not parsed.output.is_symlink(), f"matrix output path is a symlink: {parsed.output}")
        parsed.output.write_text(rendered, encoding="utf-8")
    elif parsed.write:
        require(not contract.generated_report.is_symlink(), "checked callable visibility matrix path is a symlink")
        contract.generated_report.write_text(rendered, encoding="utf-8")
    elif parsed.check:
        check_output(contract.generated_report, rendered)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MatrixError as error:
        print(f"ERROR: x86 header callable visibility matrix: {error}", file=sys.stderr)
        raise SystemExit(1)
