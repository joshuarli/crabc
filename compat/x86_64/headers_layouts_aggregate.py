#!/usr/bin/env python3
"""Check the finite, non-promoting native x86 header accounting boundary.

``libc.headers-layouts`` has a deliberately broad public-header obligation.
Its current evidence is useful but intentionally partial: generic compiler
reports make declaration differences finite, while direct probes retain
bounded layout and linkage observations.  This control joins those checked
inputs without converting a red report into a completion claim.  The native
shell wrapper runs only the reviewed runner paths emitted here; this module
then verifies the resulting digest-bound accounting report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FOUNDATION_PATH = ROOT / "compat" / "x86_64" / "headers-layouts-foundation.toml"
DIRECT_MANIFEST_PATH = ROOT / "compat" / "x86_64" / "headers-layouts.toml"
PARITY_PATH = ROOT / "compat" / "x86_64" / "parity.toml"
REPORT_PATH = ROOT / "compat" / "x86_64" / "generated" / "headers_layouts_aggregate" / "report.json"
HEADER_CALLABLE_INVENTORY_PATH = ROOT / "compat" / "x86_64" / "header_callable_inventory.json"
STATIC_C_ABI_EXPORTS_PATH = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
ACCOUNTED_INCOMPLETE_LINKAGE_AUDIT_RUNNER = "compat/x86_64/run_header_callable_linkage_audit.sh"
ACCOUNTED_INCOMPLETE_LINKAGE_AUDIT_REPORT = (
    ROOT / "compat" / "reports" / "x86_64" / "header-callable-linkage-audit" / "latest.json"
)

CONTROL_ID = "x86-headers-layouts-accounting-control"
TARGET = "x86_64-unknown-linux-musl"
PLATFORM = "Linux/x86-64 little-endian"
ORACLE = "Pinned musl 1.2.6"
REPORT_SCHEMA = "crabc.x86_64-headers-layouts-aggregate-report/v1"
FOUNDATION_SCHEMA = "crabc.x86_64-headers-layouts-foundation/v17"
DIRECT_SCHEMA = "crabc.x86_64-headers-layouts/v1"
FAMILY = "libc.headers-layouts"
DISPATCHER = "./scripts/dev-x86_64.sh"

EVIDENCE_TABLES = (
    "closure_diagnostic",
    "feature_visibility_matrix",
    "callable_feature_visibility_matrix",
    "prototype_layout_matrix",
    "record_layout_matrix",
    "callable_disposition",
    "selected_callable_provider_linkage_audit",
    "selected_header_install_projection",
    "uapi_wrapper_matrix",
    "ioctl_header_profile_matrix",
    "sys_io_header_profile_matrix",
    "epoll_header_profile_matrix",
    "event_descriptors_header_profile_matrix",
    "dirent_header_profile_matrix",
    "stdlib_header_profile_matrix",
    "timeval_transitive_header_profile_matrix",
    "sys_time_direct_header_profile_matrix",
    "access_header_profile_matrix",
    "xattr_header_profile_matrix",
)
SUPPORTING_COMMANDS = (
    "./scripts/dev-x86_64.sh musl-oracle",
    "./scripts/dev-x86_64.sh linux-5-10-uapi",
    "./scripts/dev-x86_64.sh installed-header-tree-closure",
    "./scripts/dev-x86_64.sh header-callable-linkage-audit",
)
GENERIC_REPORTS = (
    (
        "declaration-macro-visibility",
        "feature_visibility_matrix",
        "crabc.x86_64-header-declaration-macro-feature-visibility-matrix-report/v1",
        "generated_report",
    ),
    (
        "callable-visibility",
        "callable_feature_visibility_matrix",
        "crabc.x86_64-header-callable-feature-visibility-matrix-report/v1",
        "generated_report",
    ),
    (
        "prototype-layout",
        "prototype_layout_matrix",
        "crabc.x86_64-header-abi-matrix-report/v1",
        "generated_report",
    ),
    (
        "record-byte-layout",
        "record_layout_matrix",
        "crabc.x86_64-header-record-layout-matrix-report/v1",
        "generated_report",
    ),
    (
        "callable-disposition",
        "callable_disposition",
        "crabc.x86_64-header-callable-disposition-report/v1",
        "report",
    ),
)
TRACKED_INPUTS = (
    "compat/x86_64/headers-layouts-foundation.toml",
    "compat/x86_64/headers-layouts.toml",
    "compat/x86_64/parity.toml",
    "compat/x86_64/public_headers.txt",
    "compat/x86_64/static_c_abi_exports.txt",
    "compat/x86_64/header_callable_inventory.json",
    "compat/x86_64/header_callable_disposition.toml",
    "compat/x86_64/header_callable_visibility_matrix.toml",
    "compat/x86_64/header_abi_matrix.toml",
    "compat/x86_64/header_record_layout_matrix.toml",
    "compat/x86_64/header_record_layout_matrix.py",
    "compat/x86_64/header_declaration_macro_visibility_matrix.toml",
    "compat/x86_64/generated/header_declaration_macro_visibility_matrix/report.json",
    "compat/x86_64/generated/header_callable_visibility_matrix/report.json",
    "compat/x86_64/generated/header_abi_matrix/report.json",
    "compat/x86_64/generated/header_record_layout_matrix/report.json",
    "compat/x86_64/header_callable_disposition.json",
)
EXECUTION_SOURCE_INPUTS = (
    "compat/x86_64/headers_layouts_aggregate.py",
    "compat/x86_64/run_headers_layouts_aggregate.sh",
)


class AggregateError(ValueError):
    """The finite header accounting boundary is stale, incomplete, or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AggregateError(message)


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise AggregateError(f"cannot load {display_path(path)}: {error}") from error
    require(isinstance(document, dict), f"{display_path(path)} must contain a TOML table")
    return document


def load_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AggregateError(f"cannot load {display_path(path)}: {error}") from error
    require(isinstance(document, dict), f"{display_path(path)} must contain a JSON object")
    return document


def display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(65536), b""):
                digest.update(block)
    except OSError as error:
        raise AggregateError(f"cannot hash {display_path(path)}: {error}") from error
    return digest.hexdigest()


def repository_file(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty repository path")
    relative = Path(value)
    require(
        not relative.is_absolute() and ".." not in relative.parts and "\\" not in value,
        f"{location} escapes the repository",
    )
    path = ROOT / relative
    require(path.is_file() and not path.is_symlink(), f"{location} is not a regular repository file: {value}")
    return path


def repository_output(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty repository path")
    relative = Path(value)
    require(
        not relative.is_absolute() and ".." not in relative.parts and "\\" not in value,
        f"{location} escapes the repository",
    )
    parent = ROOT / relative.parent
    require(parent.is_dir() and not parent.is_symlink(), f"{location} has an unsafe parent: {relative.parent}")
    return ROOT / relative


def string_list(value: object, location: str, *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{location} must be an array")
    result: list[str] = []
    for index, item in enumerate(value):
        require(isinstance(item, str) and item, f"{location}[{index}] must be a nonempty string")
        result.append(item)
    require(allow_empty or bool(result), f"{location} must not be empty")
    require(len(result) == len(set(result)), f"{location} contains duplicates")
    return result


def mapping_list(value: object, location: str) -> list[Mapping[str, Any]]:
    require(isinstance(value, list) and value, f"{location} must be a nonempty table array")
    result: list[Mapping[str, Any]] = []
    for index, item in enumerate(value):
        require(isinstance(item, Mapping), f"{location}[{index}] must be a table")
        result.append(item)
    return result


def command_tokens(value: object, location: str) -> tuple[str, str]:
    require(isinstance(value, str) and value, f"{location} must be a nonempty command")
    try:
        tokens = shlex.split(value)
    except ValueError as error:
        raise AggregateError(f"{location} is not parseable: {error}") from error
    require(len(tokens) == 2 and tokens[0] == DISPATCHER, f"{location} must be one direct x86 dispatcher command")
    require(
        tokens[1]
        not in {
            "campaign-status",
            "campaign-family",
            "campaign-static",
            "campaign-dynamic",
            "campaign-qualification",
            "campaign-promotion-check",
            "campaign-all",
            "headers-layouts-aggregate",
        },
        f"{location} must not recurse through an aggregate or campaign command",
    )
    return tokens[0], tokens[1]


def record_file(path: Path) -> dict[str, str]:
    require(path.is_file() and not path.is_symlink(), f"aggregate input is unsafe: {display_path(path)}")
    return {"path": display_path(path), "sha256": sha256_file(path)}


def records_for_table(foundation: Mapping[str, Any], table: str) -> list[Mapping[str, Any]]:
    value = foundation.get(table)
    if isinstance(value, Mapping):
        return [value]
    return mapping_list(value, f"header foundation {table}")


def identifier_rows(value: object, location: str) -> list[str]:
    rows = mapping_list(value, location)
    identifiers: list[str] = []
    for index, row in enumerate(rows):
        identifier = row.get("id")
        require(isinstance(identifier, str) and identifier, f"{location}[{index}].id is invalid")
        identifiers.append(identifier)
    require(len(identifiers) == len(set(identifiers)), f"{location} has duplicate ids")
    return identifiers


def header_family(parity: Mapping[str, Any]) -> Mapping[str, Any]:
    families = mapping_list(parity.get("family"), "parity family")
    matches = [row for row in families if row.get("id") == FAMILY]
    require(len(matches) == 1, "parity ledger must name libc.headers-layouts exactly once")
    family = matches[0]
    require(family.get("status") == "planned", "aggregate control must retain the planned header family")
    return family


def direct_probes(manifest: Mapping[str, Any]) -> list[dict[str, str]]:
    require(manifest.get("schema") == DIRECT_SCHEMA, "direct header manifest schema drifted")
    require(manifest.get("family") == FAMILY, "direct header manifest family drifted")
    require(manifest.get("target") == TARGET, "direct header manifest target drifted")
    require(manifest.get("platform") == PLATFORM, "direct header manifest platform drifted")
    require(manifest.get("oracle") == ORACLE, "direct header manifest oracle drifted")
    require(manifest.get("status") == "planned", "direct header manifest must remain planned")
    probes = mapping_list(manifest.get("probe"), "direct header manifest probe")
    result: list[dict[str, str]] = []
    identifiers: set[str] = set()
    commands: set[str] = set()
    for index, probe in enumerate(probes):
        expected = {"id", "command", "state", "kind", "sources", "headers"}
        require(set(probe) == expected, f"direct header manifest probe[{index}] keys drifted")
        identifier = probe.get("id")
        require(isinstance(identifier, str) and identifier and identifier not in identifiers, f"direct header manifest probe[{index}].id is invalid")
        identifiers.add(identifier)
        command = probe.get("command")
        command_tokens(command, f"direct header manifest probe[{index}].command")
        require(isinstance(command, str) and command not in commands, f"direct header manifest probe[{index}].command is duplicated")
        commands.add(command)
        sources = string_list(probe.get("sources"), f"direct header manifest probe[{index}].sources")
        runners = [source for source in sources if source.endswith(".sh")]
        require(len(runners) == 1, f"direct header manifest probe[{index}] must name one shell runner")
        runner = repository_file(runners[0], f"direct header manifest probe[{index}].runner")
        for source in sources:
            repository_file(source, f"direct header manifest probe[{index}].source")
        headers = string_list(probe.get("headers"), f"direct header manifest probe[{index}].headers")
        for header in headers:
            repository_file(header, f"direct header manifest probe[{index}].header")
        result.append({"id": identifier, "command": command, "runner": display_path(runner)})
    return result


def aggregate_control(foundation: Mapping[str, Any], direct: Mapping[str, Any], parity: Mapping[str, Any]) -> dict[str, Any]:
    require(foundation.get("schema") == FOUNDATION_SCHEMA, "header foundation schema drifted")
    require(foundation.get("family") == FAMILY, "header foundation family drifted")
    require(foundation.get("target") == TARGET, "header foundation target drifted")
    require(foundation.get("platform") == PLATFORM, "header foundation platform drifted")
    require(foundation.get("oracle") == ORACLE, "header foundation oracle drifted")
    require(foundation.get("status") == "planned", "header foundation must remain planned")
    policy = foundation.get("policy")
    require(isinstance(policy, Mapping), "header foundation policy is invalid")
    require(policy.get("aggregate_family_completion") is False, "header foundation must not claim aggregate completion")
    require(policy.get("public_support") is False, "header foundation must not claim public support")

    raw_control = foundation.get("aggregate_control")
    require(isinstance(raw_control, Mapping), "header foundation aggregate control is missing")
    expected_keys = {
        "id",
        "state",
        "owner",
        "command",
        "generated_report",
        "required_result",
        "direct_manifest",
        "direct_probe_count",
        "profile_obligation_count",
        "completion_keys",
        "language_profiles",
        "header_classes",
        "abi_facets",
        "linkage_owners",
        "evidence_tables",
        "supporting_commands",
        "source_owners",
        "family_completion",
        "family_promotion",
        "public_support",
        "description",
        "runner",
    }
    require(set(raw_control) == expected_keys, "header foundation aggregate control keys drifted")
    control = dict(raw_control)
    require(control["id"] == CONTROL_ID, "aggregate control id drifted")
    require(control["state"] == "partial-verified", "aggregate control state must remain partial-verified")
    require(control["owner"] == FAMILY, "aggregate control owner drifted")
    require(control["command"] == f"{DISPATCHER} headers-layouts-aggregate", "aggregate control command drifted")
    require(control["required_result"] == "checked-accounted-partial-report", "aggregate control result contract drifted")
    require(control["family_completion"] is False, "aggregate control cannot claim family completion")
    require(control["family_promotion"] is False, "aggregate control cannot claim family promotion")
    require(control["public_support"] is False, "aggregate control cannot claim public support")
    require(isinstance(control["description"], str) and "blockers" in control["description"], "aggregate control description drifted")
    require(control["direct_manifest"] == display_path(DIRECT_MANIFEST_PATH), "aggregate control direct manifest drifted")
    repository_output(control["generated_report"], "aggregate control generated_report")
    require(int(control["direct_probe_count"]) == len(direct_probes(direct)), "aggregate control direct probe count drifted")

    completion = foundation.get("completion")
    require(isinstance(completion, Mapping), "header foundation completion is invalid")
    completion_keys = string_list(control["completion_keys"], "aggregate control completion_keys")
    require(completion_keys == sorted(completion_keys), "aggregate control completion_keys must be sorted")
    require(completion_keys == sorted(completion), "aggregate control completion coverage drifted")

    language_profiles = identifier_rows(foundation.get("language_profile"), "header foundation language_profile")
    require(string_list(control["language_profiles"], "aggregate control language_profiles") == language_profiles, "aggregate control language profile coverage drifted")
    header_classes = identifier_rows(foundation.get("header_class"), "header foundation header_class")
    require(string_list(control["header_classes"], "aggregate control header_classes") == header_classes, "aggregate control header class coverage drifted")
    abi_facets = identifier_rows(foundation.get("abi_facet"), "header foundation abi_facet")
    require(string_list(control["abi_facets"], "aggregate control abi_facets") == abi_facets, "aggregate control ABI facet coverage drifted")
    linkage_owners = identifier_rows(foundation.get("linkage_owner"), "header foundation linkage_owner")
    require(string_list(control["linkage_owners"], "aggregate control linkage_owners") == linkage_owners, "aggregate control linkage-owner coverage drifted")

    profile_obligations = mapping_list(foundation.get("profile_obligation"), "header foundation profile_obligation")
    require(int(control["profile_obligation_count"]) == len(profile_obligations), "aggregate control profile obligation count drifted")
    expected_profiles = set(language_profiles)
    expected_classes = set(header_classes)
    actual_pairs: set[tuple[str, str]] = set()
    for index, obligation in enumerate(profile_obligations):
        header_class = obligation.get("header_class")
        profile = obligation.get("profile")
        require(header_class in expected_classes, f"profile obligation {index} header class drifted")
        require(profile in expected_profiles, f"profile obligation {index} profile drifted")
        pair = (str(header_class), str(profile))
        require(pair not in actual_pairs, f"profile obligation {header_class}:{profile} is duplicated")
        actual_pairs.add(pair)
    require(actual_pairs == {(header_class, profile) for header_class in expected_classes for profile in expected_profiles}, "aggregate control profile obligation coverage drifted")

    evidence_tables = string_list(control["evidence_tables"], "aggregate control evidence_tables")
    require(tuple(evidence_tables) == EVIDENCE_TABLES, "aggregate control evidence table coverage drifted")
    evidence_commands: list[str] = []
    for table in evidence_tables:
        for record in records_for_table(foundation, table):
            command = record.get("command")
            command_tokens(command, f"header foundation {table}.command")
            assert isinstance(command, str)
            evidence_commands.append(command)
    require(len(evidence_commands) == len(set(evidence_commands)), "aggregate control evidence commands overlap")

    supporting_commands = string_list(control["supporting_commands"], "aggregate control supporting_commands")
    require(tuple(supporting_commands) == SUPPORTING_COMMANDS, "aggregate control supporting command coverage drifted")
    for index, command in enumerate(supporting_commands):
        command_tokens(command, f"aggregate control supporting_commands[{index}]")
    expected_runner_commands = evidence_commands + supporting_commands
    runners = mapping_list(control["runner"], "aggregate control runner")
    actual_runner_commands: list[str] = []
    runner_scripts: list[str] = []
    for index, runner in enumerate(runners):
        command = runner.get("command")
        expected_keys = (
            {"command", "script", "outcome"}
            if command == "./scripts/dev-x86_64.sh header-callable-linkage-audit"
            else {"command", "script"}
        )
        require(set(runner) == expected_keys, f"aggregate control runner[{index}] keys drifted")
        command_tokens(command, f"aggregate control runner[{index}].command")
        assert isinstance(command, str)
        actual_runner_commands.append(command)
        script = repository_file(runner.get("script"), f"aggregate control runner[{index}].script")
        require(script.suffix == ".sh", f"aggregate control runner[{index}].script must be a shell runner")
        script_text = display_path(script)
        if command == "./scripts/dev-x86_64.sh header-callable-linkage-audit":
            require(script_text == ACCOUNTED_INCOMPLETE_LINKAGE_AUDIT_RUNNER, "aggregate control accounted-incomplete runner drifted")
            require(runner.get("outcome") == "accounted-incomplete", "aggregate control accounted-incomplete outcome drifted")
        runner_scripts.append(script_text)
    require(actual_runner_commands == expected_runner_commands, "aggregate control runner command coverage drifted")
    require(len(runner_scripts) == len(set(runner_scripts)), "aggregate control runner scripts overlap")

    source_owners = string_list(control["source_owners"], "aggregate control source_owners")
    family = header_family(parity)
    family_owners = string_list(family.get("source_owners"), "parity header family source_owners")
    for owner in source_owners:
        require(owner in family_owners, f"aggregate control source owner is absent from parity ledger: {owner}")
    return control


def generic_reports(foundation: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for identifier, table, schema, path_key in GENERIC_REPORTS:
        value = foundation.get(table)
        require(isinstance(value, Mapping), f"header foundation {table} is invalid")
        path = repository_file(value.get(path_key), f"header foundation {table}.{path_key}")
        report = load_json(path)
        require(report.get("schema") == schema, f"generic report {identifier} schema drifted")
        require(report.get("target") == TARGET, f"generic report {identifier} target drifted")
        require(report.get("platform") == PLATFORM, f"generic report {identifier} platform drifted")
        require(report.get("oracle") == ORACLE, f"generic report {identifier} oracle drifted")
        summary = report.get("summary")
        require(isinstance(summary, Mapping), f"generic report {identifier} summary is invalid")
        if identifier == "callable-disposition":
            require(
                summary.get("candidate_external_callable_count") == 1525,
                "generic report callable-disposition candidate count drifted",
            )
        else:
            require(summary.get("profile_count") == 7, f"generic report {identifier} profile count drifted")
            require(summary.get("row_count") == 1337, f"generic report {identifier} row count drifted")
        require(summary.get("complete") is False if "complete" in summary else True, f"generic report {identifier} cannot claim completion")
        if "record_count" in value:
            require(summary.get("row_count") == value.get("record_count"), f"generic report {identifier} record count drifted")
        if "comparison_counts" in value:
            require(summary.get("comparison_counts") == value.get("comparison_counts"), f"generic report {identifier} comparison counts drifted")
        result.append(
            {
                "id": identifier,
                "path": display_path(path),
                "schema": schema,
                "sha256": sha256_file(path),
                "summary": dict(summary),
                "table": table,
            }
        )
    return result


def load_context() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, str]], list[dict[str, Any]]]:
    foundation = load_toml(FOUNDATION_PATH)
    direct = load_toml(DIRECT_MANIFEST_PATH)
    parity = load_toml(PARITY_PATH)
    control = aggregate_control(foundation, direct, parity)
    probes = direct_probes(direct)
    reports = generic_reports(foundation)
    return foundation, direct, parity, control, probes, reports


def runner_contracts() -> list[dict[str, str]]:
    """Return reviewed native runners with their explicit finite outcomes."""
    _foundation, direct, _parity, control, probes, _reports = load_context()
    runners = mapping_list(control["runner"], "aggregate control runner")
    declared = [
        {
            "outcome": str(runner.get("outcome", "pass")),
            "script": str(runner["script"]),
        }
        for runner in runners
    ]
    declared.extend({"outcome": "pass", "script": probe["runner"]} for probe in probes)
    # A direct probe can intentionally be the selected matrix runner already
    # named by the foundation. Execute that reviewed path once while retaining
    # both independent manifest records in the aggregate report.
    result: list[dict[str, str]] = []
    seen: dict[str, str] = {}
    for runner in declared:
        script = runner["script"]
        outcome = runner["outcome"]
        require(outcome in {"pass", "accounted-incomplete"}, "aggregate runner outcome is invalid")
        prior = seen.get(script)
        require(prior is None or prior == outcome, "aggregate runner outcome conflicts with a direct probe")
        if prior is None:
            seen[script] = outcome
            result.append({"outcome": outcome, "script": script})
    for index, runner in enumerate(result):
        path = repository_file(runner["script"], f"aggregate runner[{index}]")
        require(path.suffix == ".sh", f"aggregate runner[{index}] is not a shell script")
    accounted_incomplete = [runner for runner in result if runner["outcome"] == "accounted-incomplete"]
    require(
        accounted_incomplete == [{"outcome": "accounted-incomplete", "script": ACCOUNTED_INCOMPLETE_LINKAGE_AUDIT_RUNNER}],
        "aggregate accounted-incomplete runner coverage drifted",
    )
    # ``direct`` is retained in this function so callers cannot accidentally
    # turn the runner list into a detached static list.
    require(direct.get("family") == FAMILY, "direct header runner source drifted")
    return result


def runner_paths() -> list[str]:
    """Return only reviewed native runner paths, never dispatcher recursion."""
    return [runner["script"] for runner in runner_contracts()]


def tracked_input_paths() -> list[str]:
    paths = [*TRACKED_INPUTS, *EXECUTION_SOURCE_INPUTS, *runner_paths()]
    require(len(paths) == len(set(paths)), "aggregate tracked inputs overlap")
    return paths


def input_records() -> list[dict[str, str]]:
    expected_paths = tracked_input_paths()
    records = [record_file(repository_file(path, "aggregate tracked input")) for path in expected_paths]
    paths = [record["path"] for record in records]
    require(paths == expected_paths, "aggregate tracked input order drifted")
    return records


def evidence_records(foundation: Mapping[str, Any], control: Mapping[str, Any]) -> list[dict[str, str]]:
    tables = string_list(control["evidence_tables"], "aggregate control evidence_tables")
    result: list[dict[str, str]] = []
    for table in tables:
        for record in records_for_table(foundation, table):
            identifier = record.get("id")
            state = record.get("state")
            command = record.get("command")
            require(isinstance(identifier, str) and identifier, f"header foundation {table}.id is invalid")
            require(isinstance(state, str) and state, f"header foundation {table}.state is invalid")
            command_tokens(command, f"header foundation {table}.command")
            assert isinstance(command, str)
            result.append({"command": command, "id": identifier, "state": state, "table": table})
    return result


def validate_accounted_incomplete_linkage_audit_report(report: Mapping[str, Any]) -> None:
    """Require the one known red native audit to retain its finite blocker."""
    require(
        report.get("schema") == "crabc.x86_64-header-callable-linkage-audit/v2",
        "accounted-incomplete linkage audit schema drifted",
    )
    require(
        report.get("inventory_schema") == "crabc.x86_64-header-callable-inventory-report/v2",
        "accounted-incomplete linkage audit inventory schema drifted",
    )
    require(
        report.get("scope")
        == {
            "family_promotion": False,
            "feature_archive_profiles_extracted_here": False,
            "feature_archive_provider_accounting": True,
            "public_support": False,
            "uses_whole_archive": False,
        },
        "accounted-incomplete linkage audit scope drifted",
    )
    require(
        report.get("external_callable_count") == 1525
        and report.get("ratcheted_external_callable_count") == 1119,
        "accounted-incomplete linkage audit callable counts drifted",
    )
    require(
        report.get("summary")
        == {
            "callable_provider_counts": {
                "declared_unverified_feature_archives": 0,
                "default_static": 1119,
                "unprovided": 328,
                "verified_feature_archives": 78,
            },
            "complete": False,
            "extraction_status_counts": {"extracted": 1119},
            "incomplete_reasons": [
                "static export complement is nonempty",
                "one or more candidate external callables have no declared archive provider",
            ],
            "static_export_complement_count": 406,
        },
        "accounted-incomplete linkage audit must remain incomplete with the declared provider gap",
    )


def check_accounted_incomplete_linkage_audit() -> None:
    """Check fresh native evidence without weakening the standalone red audit."""
    require(
        ACCOUNTED_INCOMPLETE_LINKAGE_AUDIT_REPORT.is_file()
        and not ACCOUNTED_INCOMPLETE_LINKAGE_AUDIT_REPORT.is_symlink(),
        "accounted-incomplete linkage audit report is missing or unsafe",
    )
    report = load_json(ACCOUNTED_INCOMPLETE_LINKAGE_AUDIT_REPORT)
    validate_accounted_incomplete_linkage_audit_report(report)

    inventory_path = repository_file(
        display_path(HEADER_CALLABLE_INVENTORY_PATH),
        "accounted-incomplete linkage audit inventory",
    )
    static_exports_path = repository_file(
        display_path(STATIC_C_ABI_EXPORTS_PATH),
        "accounted-incomplete linkage audit static exports",
    )
    inventory = load_json(inventory_path)
    require(
        report.get("inventory_static_export_digest") == sha256_file(static_exports_path),
        "accounted-incomplete linkage audit static-export digest is stale",
    )
    partition = inventory.get("callable_provider_partition")
    require(
        isinstance(partition, Mapping)
        and report.get("callable_provider_partition") == partition,
        "accounted-incomplete linkage audit provider partition is stale",
    )
    default_static = partition.get("default_static")
    require(isinstance(default_static, Mapping), "accounted-incomplete linkage audit default provider is invalid")
    expected_members = default_static.get("members")
    require(isinstance(expected_members, list), "accounted-incomplete linkage audit default members are invalid")
    extraction = report.get("archive_extraction")
    require(isinstance(extraction, list), "accounted-incomplete linkage audit extraction is invalid")
    require(
        [record.get("symbol") if isinstance(record, Mapping) else None for record in extraction]
        == expected_members
        and all(isinstance(record, Mapping) and record.get("status") == "extracted" for record in extraction),
        "accounted-incomplete linkage audit extraction evidence drifted",
    )


def blockers(foundation: Mapping[str, Any], reports: Sequence[Mapping[str, Any]]) -> tuple[list[str], dict[str, int]]:
    by_id = {str(report["id"]): report for report in reports}
    declaration = by_id["declaration-macro-visibility"]["summary"]
    callable_visibility = by_id["callable-visibility"]["summary"]
    prototype = by_id["prototype-layout"]["summary"]
    record_layout = by_id["record-byte-layout"]["summary"]
    disposition = by_id["callable-disposition"]["summary"]
    require(isinstance(declaration, Mapping), "declaration summary is invalid")
    require(isinstance(callable_visibility, Mapping), "callable visibility summary is invalid")
    require(isinstance(prototype, Mapping), "prototype summary is invalid")
    require(isinstance(record_layout, Mapping), "record byte-layout summary is invalid")
    require(isinstance(disposition, Mapping), "callable disposition summary is invalid")
    record_layout_comparisons = record_layout.get("comparison_counts")
    require(
        isinstance(record_layout_comparisons, Mapping),
        "record byte-layout comparison summary is invalid",
    )
    counts = {
        "callable_provider_unprovided": int(disposition.get("unprovided_callable_count", -1)),
        "callable_visibility_mismatch_rows": int(callable_visibility.get("mismatch_row_count", -1)),
        "declaration_identity_mismatch_rows": int(declaration.get("mismatch_row_count", -1)),
        "declaration_source_form_differences": int(declaration.get("source_form_difference_count", -1)),
        "prototype_or_named_declaration_mismatch_rows": int(prototype.get("mismatch_row_count", -1)),
        # A zero-valued comparison category is intentionally absent from the
        # deterministic record report. Treat that omission as zero rather than
        # a malformed blocker, while retaining the negative default for fields
        # that are required to be present.
        "record_byte_layout_mismatch_rows": int(record_layout_comparisons.get("mismatch", 0)),
    }
    require(all(value >= 0 for value in counts.values()), "generic blocker count is invalid")
    completion = foundation.get("completion")
    require(isinstance(completion, Mapping), "header foundation completion is invalid")
    require(completion.get("abi_facet_matrix") is False, "header foundation ABI facet completion drifted")
    require(completion.get("callable_linkage_audit") is False, "header foundation callable linkage completion drifted")
    require(completion.get("runtime_completion") is False, "header foundation runtime completion drifted")
    require(completion.get("family_promotion") is False, "header foundation family promotion drifted")
    return (
        [
            "declaration-macro-identity",
            "declaration-source-forms",
            "callable-visibility",
            "prototype-or-named-declarations",
            "callable-provider-closure",
            "record-byte-layouts",
            "runtime-semantics",
            "family-promotion",
        ],
        counts,
    )


def build_report() -> dict[str, Any]:
    """Build the deterministic partial-accounting report from checked inputs."""
    foundation, _direct, _parity, control, probes, reports = load_context()
    completion = foundation.get("completion")
    require(isinstance(completion, Mapping), "header foundation completion is invalid")
    block_ids, block_counts = blockers(foundation, reports)
    return {
        "abi_facet_count": len(string_list(control["abi_facets"], "aggregate control abi_facets")),
        "accounting_complete": True,
        "blocker_counts": block_counts,
        "blockers": block_ids,
        "completion_coverage": [
            {"key": key, "value": completion[key]}
            for key in string_list(control["completion_keys"], "aggregate control completion_keys")
        ],
        "control": {
            "id": control["id"],
            "required_result": control["required_result"],
            "state": control["state"],
        },
        "direct_probe_count": len(probes),
        "direct_probes": probes,
        "evidence": evidence_records(foundation, control),
        "family": FAMILY,
        "family_completion": False,
        "generic_reports": reports,
        "header_classes": string_list(control["header_classes"], "aggregate control header_classes"),
        "inputs": input_records(),
        "language_profile_count": len(string_list(control["language_profiles"], "aggregate control language_profiles")),
        "language_profiles": string_list(control["language_profiles"], "aggregate control language_profiles"),
        "linkage_owner_count": len(string_list(control["linkage_owners"], "aggregate control linkage_owners")),
        "linkage_owners": string_list(control["linkage_owners"], "aggregate control linkage_owners"),
        "oracle": ORACLE,
        "platform": PLATFORM,
        "profile_obligation_count": int(control["profile_obligation_count"]),
        "promotion_ready": False,
        "public_support": False,
        "schema": REPORT_SCHEMA,
        "scope": "finite native x86 header accounting only; no family completion, product admission, promotion, or public support",
        "target": TARGET,
    }


def report_inputs_are_current(value: object) -> None:
    records = value
    require(isinstance(records, list) and records, "aggregate report inputs are invalid")
    expected_paths = tracked_input_paths()
    actual_paths: list[str] = []
    for index, record in enumerate(records):
        require(isinstance(record, Mapping) and set(record) == {"path", "sha256"}, f"aggregate report input[{index}] is invalid")
        path = record.get("path")
        digest = record.get("sha256")
        require(isinstance(path, str) and isinstance(digest, str) and len(digest) == 64, f"aggregate report input[{index}] digest is invalid")
        actual_paths.append(path)
        current = sha256_file(repository_file(path, f"aggregate report input[{index}].path"))
        require(current == digest, f"aggregate report input digest is stale: {path}")
    require(actual_paths == expected_paths, "aggregate report input coverage drifted")


def validate_report(report: Mapping[str, Any]) -> None:
    """Reject stale input digests and every accidental completion implication."""
    expected_keys = {
        "abi_facet_count",
        "accounting_complete",
        "blocker_counts",
        "blockers",
        "completion_coverage",
        "control",
        "direct_probe_count",
        "direct_probes",
        "evidence",
        "family",
        "family_completion",
        "generic_reports",
        "header_classes",
        "inputs",
        "language_profile_count",
        "language_profiles",
        "linkage_owner_count",
        "linkage_owners",
        "oracle",
        "platform",
        "profile_obligation_count",
        "promotion_ready",
        "public_support",
        "schema",
        "scope",
        "target",
    }
    require(set(report) == expected_keys, "aggregate report top-level keys drifted")
    require(report.get("schema") == REPORT_SCHEMA, "aggregate report schema drifted")
    require(report.get("family") == FAMILY, "aggregate report family drifted")
    require(report.get("target") == TARGET, "aggregate report target drifted")
    require(report.get("platform") == PLATFORM, "aggregate report platform drifted")
    require(report.get("oracle") == ORACLE, "aggregate report oracle drifted")
    require(report.get("accounting_complete") is True, "aggregate report must retain finite accounting")
    require(report.get("family_completion") is False, "aggregate report cannot claim family completion")
    require(report.get("promotion_ready") is False, "aggregate report cannot claim promotion readiness")
    require(report.get("public_support") is False, "aggregate report cannot claim public support")
    require(isinstance(report.get("scope"), str) and "no family completion" in report["scope"], "aggregate report scope drifted")
    report_inputs_are_current(report.get("inputs"))

    _foundation, _direct, _parity, control, probes, expected_reports = load_context()
    control_value = report.get("control")
    require(isinstance(control_value, Mapping), "aggregate report control is invalid")
    require(
        dict(control_value)
        == {"id": CONTROL_ID, "required_result": "checked-accounted-partial-report", "state": "partial-verified"},
        "aggregate report control drifted",
    )
    require(report.get("direct_probe_count") == len(probes), "aggregate report direct probe count drifted")
    require(report.get("direct_probes") == probes, "aggregate report direct probe coverage drifted")
    require(report.get("profile_obligation_count") == control["profile_obligation_count"], "aggregate report profile obligation count drifted")
    require(report.get("language_profiles") == control["language_profiles"], "aggregate report language profile coverage drifted")
    require(report.get("language_profile_count") == len(control["language_profiles"]), "aggregate report language profile count drifted")
    require(report.get("header_classes") == control["header_classes"], "aggregate report header class coverage drifted")
    require(report.get("abi_facet_count") == len(control["abi_facets"]), "aggregate report ABI facet count drifted")
    require(report.get("linkage_owners") == control["linkage_owners"], "aggregate report linkage owner coverage drifted")
    require(report.get("linkage_owner_count") == len(control["linkage_owners"]), "aggregate report linkage owner count drifted")

    generic = report.get("generic_reports")
    require(isinstance(generic, list), "aggregate report generic reports are invalid")
    expected_ids = [item["id"] for item in expected_reports]
    actual_ids = [item.get("id") if isinstance(item, Mapping) else None for item in generic]
    require(actual_ids == expected_ids, "aggregate report generic report coverage drifted")
    require(generic == expected_reports, "aggregate report generic report content drifted")

    expected = build_report()
    require(report.get("completion_coverage") == expected["completion_coverage"], "aggregate report completion coverage drifted")
    require(report.get("evidence") == expected["evidence"], "aggregate report evidence coverage drifted")
    require(report.get("blockers") == expected["blockers"], "aggregate report blockers drifted")
    require(report.get("blocker_counts") == expected["blocker_counts"], "aggregate report blocker counts drifted")


def render_report(report: Mapping[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def check_output(expected: Mapping[str, Any], path: Path = REPORT_PATH) -> None:
    """Require the committed output to equal current inputs byte-for-byte."""
    try:
        actual = load_json(path)
        validate_report(actual)
    except AggregateError as error:
        raise AggregateError(f"aggregate output drifted: {error}") from error
    require(render_report(actual) == render_report(expected), "aggregate output drifted")


def write_output(report: Mapping[str, Any], path: Path = REPORT_PATH) -> None:
    require(path.parent.is_dir() and not path.parent.is_symlink(), "aggregate report parent is unsafe")
    path.write_text(render_report(report), encoding="utf-8")


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="validate the committed aggregate report")
    mode.add_argument("--write", action="store_true", help="write the aggregate report from current checked inputs")
    mode.add_argument("--runner-list", action="store_true", help="emit reviewed native runner paths")
    mode.add_argument("--runner-contract-list", action="store_true", help="emit reviewed native runner paths with outcomes")
    mode.add_argument(
        "--check-accounted-incomplete-linkage-audit",
        action="store_true",
        help="validate the one deliberate incomplete native linkage report",
    )
    mode.add_argument("--print", action="store_true", help="print the current aggregate report")
    parsed = parser.parse_args(arguments)
    try:
        if parsed.runner_list:
            print("\n".join(runner_paths()))
            return 0
        if parsed.runner_contract_list:
            print("\n".join(f"{runner['script']}\t{runner['outcome']}" for runner in runner_contracts()))
            return 0
        if parsed.check_accounted_incomplete_linkage_audit:
            check_accounted_incomplete_linkage_audit()
            print("x86 headers/layouts aggregate: ACCOUNTED-INCOMPLETE (declared callable-provider gap)")
            return 0
        report = build_report()
        if parsed.write:
            write_output(report)
            print("x86 headers/layouts aggregate: wrote checked partial accounting report")
            return 0
        if parsed.check:
            check_output(report)
            print("x86 headers/layouts aggregate: PASS (finite accounting; family remains planned)")
            return 0
        print(render_report(report), end="")
        return 0
    except AggregateError as error:
        print(f"x86 headers/layouts aggregate: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
