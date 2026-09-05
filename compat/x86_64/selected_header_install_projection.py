#!/usr/bin/env python3
"""Validate the private x86 selected installed-header projection contract.

The shared repository ``include/`` tree intentionally carries a small set of
project-only headers for other in-tree consumers.  This contract neither
removes nor reclassifies those paths.  It fixes the smaller x86 installed
surface to the 183 path musl 1.2.6 inventory and makes every source-only
pathname an explicit exclusion before the native compiler evidence runs.
"""

from __future__ import annotations

import argparse
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


EXPECTED_SCHEMA = "crabc.x86_64-selected-header-install-projection/v1"
EXPECTED_TARGET = "x86_64-unknown-linux-musl"
EXPECTED_PLATFORM = "Linux/x86-64 little-endian"
EXPECTED_FAMILY = "libc.headers-layouts"
EXPECTED_TARGET_OBLIGATION = "project-only-extension-policy"
EXPECTED_PROFILE_COUNT = 7
EXPECTED_PROJECTION_ROW_COUNT = 1281
EXPECTED_SELECTED_HEADER_COUNT = 183
EXPECTED_EXCLUDED_HEADER_COUNT = 8
EXPECTED_DISPOSITION = "excluded-from-x86-selected-install-surface"


class ProjectionError(ValueError):
    """Raised when the checked-in projection cannot name its exact surface."""


@dataclass(frozen=True)
class ExcludedHeader:
    """A project-tree header deliberately absent from the x86 install image."""

    path: str
    disposition: str
    origin: str
    canonical_surface: str
    capability_family: str
    provider_state: str
    reason: str


@dataclass(frozen=True)
class ProjectionContract:
    """The finite selected-header materialization contract."""

    target_family: str
    target_obligation: str
    selected_headers: tuple[str, ...]
    exclusions: tuple[ExcludedHeader, ...]
    profile_count: int
    projection_row_count: int


def load_toml(path: Path) -> dict[str, Any]:
    """Load one TOML contract while retaining a mutable test-friendly mapping."""

    try:
        with path.open("rb") as source:
            data = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ProjectionError(f"cannot load selected-header projection {path}: {error}") from error
    if not isinstance(data, dict):
        raise ProjectionError("selected-header projection root must be a table")
    return data


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProjectionError(message)


def _require_string(value: Any, label: str) -> str:
    _require(isinstance(value, str) and value != "", f"{label} must be a non-empty string")
    return value


def _relative_path(value: str, label: str) -> None:
    _require(
        not value.startswith("/")
        and ".." not in value.split("/")
        and "\\" not in value
        and "\t" not in value
        and "\r" not in value
        and "\n" not in value,
        f"{label} must be a safe repository-relative pathname",
    )


def _repository_root(contract_path: Path) -> Path:
    # ``compat/x86_64/<contract>`` is intentionally a fixed repository seam.
    root = contract_path.resolve().parents[2]
    _require((root / "include").is_dir(), "selected-header projection repository root lacks include/")
    return root


def _read_inventory(path: Path) -> tuple[str, ...]:
    try:
        lines = tuple(path.read_text(encoding="utf-8").splitlines())
    except OSError as error:
        raise ProjectionError(f"cannot read pinned public-header inventory {path}: {error}") from error
    _require(lines, "pinned public-header inventory must not be empty")
    _require(lines == tuple(sorted(lines)), "pinned public-header inventory must be sorted")
    _require(len(lines) == len(set(lines)), "pinned public-header inventory contains duplicate paths")
    for path in lines:
        _relative_path(path, "pinned public-header inventory entry")
        _require(path.endswith(".h"), "pinned public-header inventory entry must end in .h")
        _require(not path.startswith("bits/"), "pinned public-header inventory must not select bits/**")
    return lines


def _source_non_bits_headers(source_root: Path) -> tuple[str, ...]:
    _require(source_root.is_dir() and not source_root.is_symlink(), "source header root must be a directory")
    paths: list[str] = []
    for path in source_root.rglob("*.h"):
        _require(not path.is_symlink(), f"source header path must not be a symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(source_root).as_posix()
        if relative.startswith("bits/"):
            continue
        _relative_path(relative, "source non-bits header")
        paths.append(relative)
    return tuple(sorted(paths))


def _parse_exclusions(raw: Any) -> tuple[ExcludedHeader, ...]:
    _require(isinstance(raw, list), "excluded_header must be an array")
    exclusions: list[ExcludedHeader] = []
    required_keys = {
        "path",
        "disposition",
        "origin",
        "canonical_surface",
        "capability_family",
        "provider_state",
        "reason",
    }
    for index, item in enumerate(raw):
        _require(isinstance(item, Mapping), f"excluded_header[{index}] must be a table")
        _require(
            set(item) == required_keys,
            f"excluded_header[{index}] keys drifted",
        )
        path = _require_string(item["path"], f"excluded_header[{index}].path")
        _relative_path(path, f"excluded_header[{index}].path")
        _require(path.endswith(".h"), f"excluded_header[{index}].path must end in .h")
        exclusions.append(
            ExcludedHeader(
                path=path,
                disposition=_require_string(
                    item["disposition"], f"excluded_header[{index}].disposition"
                ),
                origin=_require_string(item["origin"], f"excluded_header[{index}].origin"),
                canonical_surface=_require_string(
                    item["canonical_surface"],
                    f"excluded_header[{index}].canonical_surface",
                ),
                capability_family=_require_string(
                    item["capability_family"],
                    f"excluded_header[{index}].capability_family",
                ),
                provider_state=_require_string(
                    item["provider_state"], f"excluded_header[{index}].provider_state"
                ),
                reason=_require_string(item["reason"], f"excluded_header[{index}].reason"),
            )
        )
    paths = tuple(entry.path for entry in exclusions)
    _require(paths == tuple(sorted(paths)), "excluded_header entries must be sorted by path")
    _require(len(paths) == len(set(paths)), "excluded_header entries contain duplicate paths")
    _require(
        all(entry.disposition == EXPECTED_DISPOSITION for entry in exclusions),
        "excluded_header disposition must close the x86 selected install surface",
    )
    return tuple(exclusions)


def _validate_work_package(raw: Any) -> tuple[str, str]:
    _require(isinstance(raw, Mapping), "work_package must be a table")
    required_keys = {
        "target_family",
        "target_obligation",
        "blocker",
        "prerequisites",
        "dependents",
        "baseline",
        "ownership",
        "focused_evidence_command",
        "family_aggregate",
        "product_command",
        "negative_scope",
        "expected_transition",
    }
    _require(set(raw) == required_keys, "work_package keys drifted")
    target_family = _require_string(raw["target_family"], "work_package.target_family")
    target_obligation = _require_string(
        raw["target_obligation"], "work_package.target_obligation"
    )
    _require(target_family == EXPECTED_FAMILY, "work_package target family drifted")
    _require(
        target_obligation == EXPECTED_TARGET_OBLIGATION,
        "work_package target obligation drifted",
    )
    for key in (
        "blocker",
        "baseline",
        "focused_evidence_command",
        "family_aggregate",
        "product_command",
        "negative_scope",
        "expected_transition",
    ):
        _require_string(raw[key], f"work_package.{key}")
    for key in ("prerequisites", "dependents", "ownership"):
        values = raw[key]
        _require(isinstance(values, list) and values, f"work_package.{key} must be a non-empty array")
        for value in values:
            _require_string(value, f"work_package.{key} entry")
    _require(
        raw["focused_evidence_command"]
        == "./scripts/dev-x86_64.sh selected-header-install-projection",
        "work_package must name the dedicated native command",
    )
    _require(
        "completed header foundation" in raw["expected_transition"]
        and "provider/archive closure" in raw["expected_transition"],
        "work_package expected transition must retain downstream C-ABI closure",
    )
    return target_family, target_obligation


def parse_contract(raw: Mapping[str, Any], contract_path: Path) -> ProjectionContract:
    """Parse and fail closed over the source-only public-header complement."""

    expected_keys = {
        "schema",
        "family",
        "target",
        "platform",
        "oracle",
        "source_header_root",
        "pinned_public_inventory",
        "selected_public_header_count",
        "excluded_project_only_header_count",
        "profile_count",
        "projection_row_count",
        "bits_policy",
        "source_tree_mutation",
        "negative_scope",
        "work_package",
        "excluded_header",
    }
    _require(set(raw) == expected_keys, "selected-header projection top-level keys drifted")
    _require(raw["schema"] == EXPECTED_SCHEMA, "selected-header projection schema drifted")
    _require(raw["family"] == EXPECTED_FAMILY, "selected-header projection family drifted")
    _require(raw["target"] == EXPECTED_TARGET, "selected-header projection target drifted")
    _require(raw["platform"] == EXPECTED_PLATFORM, "selected-header projection platform drifted")
    _require(raw["oracle"] == "Pinned musl 1.2.6", "selected-header projection oracle drifted")
    _require(
        raw["source_header_root"] == "include",
        "selected-header projection source header root drifted",
    )
    _require(
        raw["pinned_public_inventory"] == "compat/x86_64/public_headers.txt",
        "selected-header projection pinned inventory path drifted",
    )
    _require(
        raw["selected_public_header_count"] == EXPECTED_SELECTED_HEADER_COUNT,
        "selected public-header count drifted",
    )
    _require(
        raw["excluded_project_only_header_count"] == EXPECTED_EXCLUDED_HEADER_COUNT,
        "excluded project-only header count drifted",
    )
    _require(raw["profile_count"] == EXPECTED_PROFILE_COUNT, "projection profile count drifted")
    _require(
        raw["projection_row_count"] == EXPECTED_PROJECTION_ROW_COUNT,
        "projection row count drifted",
    )
    _require(
        raw["projection_row_count"]
        == raw["selected_public_header_count"] * raw["profile_count"],
        "projection row arithmetic must close exactly",
    )
    _require(
        raw["bits_policy"] == "retain-all-project-bits-private-headers",
        "selected-header projection bits policy drifted",
    )
    _require(raw["source_tree_mutation"] is False, "selected-header projection must not mutate include/")
    _require_string(raw["negative_scope"], "negative_scope")
    target_family, target_obligation = _validate_work_package(raw["work_package"])
    exclusions = _parse_exclusions(raw["excluded_header"])

    root = _repository_root(contract_path)
    inventory_path = root / raw["pinned_public_inventory"]
    selected_headers = _read_inventory(inventory_path)
    _require(
        len(selected_headers) == raw["selected_public_header_count"],
        "selected public-header inventory count drifted",
    )
    source_root = root / raw["source_header_root"]
    source_non_bits = _source_non_bits_headers(source_root)
    selected_set = set(selected_headers)
    excluded_set = {entry.path for entry in exclusions}
    _require(
        not selected_set & excluded_set,
        "selected and excluded header sets must not overlap",
    )
    _require(
        set(source_non_bits) == selected_set | excluded_set,
        "source-only header roster must exactly equal the declared exclusions",
    )
    _require(
        len(exclusions) == raw["excluded_project_only_header_count"],
        "excluded project-only header count does not match exclusions",
    )
    for header in selected_headers:
        path = source_root / header
        _require(path.is_file() and not path.is_symlink(), f"selected header is absent or unsafe: {header}")
    for exclusion in exclusions:
        path = source_root / exclusion.path
        _require(path.is_file() and not path.is_symlink(), f"excluded header is absent or unsafe: {exclusion.path}")
    bits_root = source_root / "bits"
    _require(bits_root.is_dir() and not bits_root.is_symlink(), "source bits/ root must be present")

    return ProjectionContract(
        target_family=target_family,
        target_obligation=target_obligation,
        selected_headers=selected_headers,
        exclusions=exclusions,
        profile_count=raw["profile_count"],
        projection_row_count=raw["projection_row_count"],
    )


def load_contract(path: Path) -> ProjectionContract:
    """Load the checked projection and prove it still covers source ``include/``."""

    return parse_contract(load_toml(path), path)


def _emit_paths(paths: Sequence[str]) -> None:
    for path in paths:
        print(path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--contract",
        type=Path,
        default=Path(__file__).with_name("selected-header-install-projection.toml"),
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true", help="validate and print the closed summary")
    action.add_argument("--selected-paths", action="store_true", help="print selected public paths")
    action.add_argument("--excluded-paths", action="store_true", help="print excluded source-only paths")
    args = parser.parse_args(argv)

    try:
        contract = load_contract(args.contract)
    except ProjectionError as error:
        parser.error(str(error))

    if args.selected_paths:
        _emit_paths(contract.selected_headers)
    elif args.excluded_paths:
        _emit_paths(tuple(entry.path for entry in contract.exclusions))
    else:
        print(
            "selected-header install projection: PASS "
            f"({len(contract.selected_headers)} selected paths * "
            f"{contract.profile_count} profiles = {contract.projection_row_count} rows; "
            f"{len(contract.exclusions)} source-only exclusions)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
