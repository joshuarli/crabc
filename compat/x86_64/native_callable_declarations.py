#!/usr/bin/env python3
"""Account selected native callable declaration forms without selecting providers.

This adapter consumes the one envelope already returned by
``header_declaration_inventory.validate_report`` and a matrix projection that
``native_abi_selection`` derived after validating the checked header ABI
matrix.  It never runs a compiler, replays raw compiler evidence, parses a
header, infers language linkage, or chooses an archive/shared provider.

The selected-name partition remains owned by ``header_callable_disposition``.
This module deliberately records raw physical FunctionDecl observations and
their exact type/linker-spelling agreement only.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import copy
from pathlib import Path
import re
import sys
import tomllib
from typing import Any, Mapping, Sequence


MODULE_DIRECTORY = Path(__file__).resolve().parent
if str(MODULE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(MODULE_DIRECTORY))

import header_callable_extension_contract as callable_extension_contract
import header_declaration_inventory as declaration_inventory


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "native_callable_declarations.toml"
SCHEMA = "crabc.x86_64-native-callable-declarations/v1"
MATRIX_PROJECTION_SCHEMA = "crabc.x86_64-native-callable-matrix-projection/v1"
HEADER_REPORT_SCHEMA = "crabc.x86_64-header-declaration-inventory/v1"
HEADER_MATRIX_REPORT_SCHEMA = "crabc.x86_64-header-abi-matrix-report/v2"
TARGET = "x86_64-unknown-linux-musl"
ORACLE = "Pinned musl 1.2.6"

PROFILE_LANGUAGES = {
    "c11-gnu": "c",
    "cxx17-gnu": "cxx",
    "c11-strict": "c",
    "c11-posix-2008": "c",
    "c11-xopen-700": "c",
    "c11-bsd": "c",
    "cxx17-strict": "cxx",
}
POLICY = {
    "exact_qual_type_and_linker_spelling_multisets": True,
    "physical_raw_function_provenance": True,
    "provider_selection": False,
    "raw_occurrence_multiplicity_preserved": True,
    "replay_or_compiler_execution": False,
    "semantic_language_linkage": False,
    "synthetic_macro_or_gcc_fallback_declarations": False,
    "family_completion": False,
    "public_support": False,
}
MATRIX_COMPARISONS = {
    "matched",
    "candidate-only-reviewed-native-callable-extension",
    "candidate-only-reviewed-project-c-abi-extension",
    "oracle-not-applicable",
}
DEFERRED_RESOLUTIONS = {
    "planned-provider",
    "compiler-builtin",
    "consumer-supplied",
    "oracle-declared-no-provider",
    "policy-decision-required",
}
SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HEADER_REPORT_KEYS = {
    "collection",
    "final_active_macros",
    "inputs",
    "jobs",
    "macro_events",
    "occurrences",
    "oracle",
    "platform",
    "schema",
    "scope",
    "status",
    "summary",
    "target",
}
RAW_FUNCTION_KEYS = {
    "ast_node_ordinal",
    "definition_observation",
    "input_header",
    "kind",
    "linkage_specifier_languages",
    "linkage_status",
    "mangled_name_observation",
    "name",
    "occurrence_ordinal",
    "previous_declaration",
    "profile",
    "raw_ast_path",
    "raw_node_id_observation",
    "source",
    "source_language",
    "storage_class_observation",
    "tls_observation",
    "tree",
    "type",
    "unmodeled_node_keys",
}
RAW_SOURCE_KEYS = {
    "column",
    "declaring_header",
    "include_root",
    "line",
    "offset",
    "origin_resolution",
    "token_length",
}


class NativeCallableDeclarationsError(ValueError):
    """The selected callable declaration account is malformed or differs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeCallableDeclarationsError(message)


def exact_keys(value: object, keys: set[str], description: str) -> Mapping[str, Any]:
    require(isinstance(value, Mapping) and set(value) == keys, f"{description} fields differ")
    return value


def string(value: object, description: str, *, empty: bool = False) -> str:
    require(isinstance(value, str) and (empty or bool(value)), f"{description} is not a string")
    return value


def positive_integer(value: object, description: str, *, zero: bool = False) -> int:
    require(type(value) is int and (value >= 0 if zero else value > 0), f"{description} is not an integer")
    return value


def safe_relative(value: object, description: str) -> str:
    result = string(value, description)
    path = Path(result)
    require(not path.is_absolute() and ".." not in path.parts and path.as_posix() == result, f"{description} is not a safe relative path")
    return result


def symbol(value: object, description: str) -> str:
    result = string(value, description)
    require(SYMBOL.fullmatch(result) is not None, f"{description} is not a C identifier")
    return result


def _load_toml(path: Path) -> Mapping[str, Any]:
    try:
        with path.open("rb") as stream:
            result = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise NativeCallableDeclarationsError(f"cannot load {path}: {error}") from error
    require(isinstance(result, Mapping), "native callable declaration contract is not a table")
    return result


def _boolean_policy(value: object) -> dict[str, bool]:
    raw = exact_keys(value, set(POLICY), "native callable declaration policy")
    result: dict[str, bool] = {}
    for key, expected in POLICY.items():
        actual = raw[key]
        require(type(actual) is bool and actual is expected, f"native callable declaration policy.{key} differs")
        result[key] = actual
    return result


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    """Load the small reviewed declaration-form policy strictly."""
    raw = exact_keys(
        _load_toml(path),
        {
            "schema",
            "target",
            "oracle",
            "header_declaration_report_schema",
            "header_abi_matrix_report_schema",
            "matrix_projection_schema",
            "profile_languages",
            "policy",
        },
        "native callable declaration contract",
    )
    require(raw["schema"] == SCHEMA, "native callable declaration contract schema differs")
    require(raw["target"] == TARGET, "native callable declaration contract target differs")
    require(raw["oracle"] == ORACLE, "native callable declaration contract oracle differs")
    require(raw["header_declaration_report_schema"] == HEADER_REPORT_SCHEMA, "native callable declaration report schema differs")
    require(raw["header_abi_matrix_report_schema"] == HEADER_MATRIX_REPORT_SCHEMA, "native callable matrix report schema differs")
    require(raw["matrix_projection_schema"] == MATRIX_PROJECTION_SCHEMA, "native callable matrix projection schema differs")
    languages = exact_keys(raw["profile_languages"], set(PROFILE_LANGUAGES), "native callable declaration profile languages")
    require(dict(languages) == PROFILE_LANGUAGES, "native callable declaration profile languages differ")
    return {
        "schema": SCHEMA,
        "target": TARGET,
        "oracle": ORACLE,
        "header_declaration_report_schema": HEADER_REPORT_SCHEMA,
        "header_abi_matrix_report_schema": HEADER_MATRIX_REPORT_SCHEMA,
        "matrix_projection_schema": MATRIX_PROJECTION_SCHEMA,
        "profile_languages": copy.deepcopy(PROFILE_LANGUAGES),
        "policy": _boolean_policy(raw["policy"]),
    }


def _reviewed_contract(contract: Mapping[str, Any] | None) -> dict[str, Any]:
    canonical = load_contract()
    if contract is not None:
        require(isinstance(contract, Mapping), "native callable declaration contract is invalid")
        require(
            declaration_inventory.strict_equal(contract, canonical),
            "supplied callable declaration contract differs from reviewed canonical contract",
        )
    return canonical


def _file_identity(value: object, description: str) -> dict[str, Any]:
    raw = exact_keys(value, {"path", "sha256", "size", "mode"}, description)
    path = safe_relative(raw["path"], f"{description}.path")
    digest = string(raw["sha256"], f"{description}.sha256")
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, f"{description}.sha256 is invalid")
    size = positive_integer(raw["size"], f"{description}.size", zero=True)
    mode = positive_integer(raw["mode"], f"{description}.mode", zero=True)
    return {"path": path, "sha256": digest, "size": size, "mode": mode}


def matrix_projection_from_checked_report(
    report: Mapping[str, Any],
    *,
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    """Project an already validated matrix without invoking its collector.

    ``native_abi_selection.load_source_inputs`` first calls the matrix's public
    checked-report validator.  This deliberately small projection then carries
    only the row classification needed to place raw FunctionDecl occurrences.
    """
    require(isinstance(report, Mapping) and report.get("schema") == HEADER_MATRIX_REPORT_SCHEMA, "checked matrix report schema differs")
    raw_provenance = exact_keys(provenance, {"report", "reader", "contract", "extension_contract"}, "callable matrix provenance")
    checked_provenance = {key: _file_identity(raw_provenance[key], f"callable matrix provenance.{key}") for key in sorted(raw_provenance)}
    rows = report.get("rows")
    require(isinstance(rows, list) and bool(rows), "checked matrix rows are absent")
    result_rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, row in enumerate(rows):
        require(isinstance(row, Mapping), f"checked matrix row {index} is invalid")
        header = safe_relative(row.get("header"), f"checked matrix row {index}.header")
        profile = string(row.get("profile"), f"checked matrix row {index}.profile")
        require(profile in PROFILE_LANGUAGES, f"checked matrix row {index}.profile is unknown")
        comparison = string(row.get("comparison"), f"checked matrix row {index}.comparison")
        require(comparison in MATRIX_COMPARISONS, f"checked matrix row {index}.comparison is unusable")
        reference_status = string(row.get("reference_status"), f"checked matrix row {index}.reference_status")
        key = (header, profile)
        require(key not in seen, f"checked matrix row repeats {header}:{profile}")
        seen.add(key)
        result_rows.append(
            {
                "header": header,
                "profile": profile,
                "comparison": comparison,
                "reference_status": reference_status,
            }
        )
    return {
        "schema": MATRIX_PROJECTION_SCHEMA,
        "provenance": checked_provenance,
        "rows": result_rows,
    }


def _validate_matrix_projection(value: object) -> tuple[dict[tuple[str, str], dict[str, str]], dict[str, Any]]:
    raw = exact_keys(value, {"schema", "provenance", "rows"}, "callable matrix projection")
    require(raw["schema"] == MATRIX_PROJECTION_SCHEMA, "callable matrix projection schema differs")
    provenance_raw = exact_keys(raw["provenance"], {"report", "reader", "contract", "extension_contract"}, "callable matrix projection provenance")
    provenance = {key: _file_identity(provenance_raw[key], f"callable matrix projection provenance.{key}") for key in sorted(provenance_raw)}
    expected_paths = {
        "report": "compat/x86_64/generated/header_abi_matrix/report.json",
        "reader": "compat/x86_64/header_abi_matrix.py",
        "contract": "compat/x86_64/header_abi_matrix.toml",
        "extension_contract": "compat/x86_64/header_callable_extension_contract.toml",
    }
    require({key: provenance[key]["path"] for key in expected_paths} == expected_paths, "callable matrix projection provenance paths differ")
    rows = raw["rows"]
    require(isinstance(rows, list) and bool(rows), "callable matrix projection rows are absent")
    by_key: dict[tuple[str, str], dict[str, str]] = {}
    for index, item in enumerate(rows):
        row = exact_keys(item, {"header", "profile", "comparison", "reference_status"}, f"callable matrix projection row {index}")
        header = safe_relative(row["header"], f"callable matrix projection row {index}.header")
        profile = string(row["profile"], f"callable matrix projection row {index}.profile")
        require(profile in PROFILE_LANGUAGES, f"callable matrix projection row {index}.profile is unknown")
        comparison = string(row["comparison"], f"callable matrix projection row {index}.comparison")
        require(comparison in MATRIX_COMPARISONS, f"callable matrix projection row {index}.comparison is unusable")
        reference_status = string(row["reference_status"], f"callable matrix projection row {index}.reference_status")
        if comparison in {"matched", "candidate-only-reviewed-native-callable-extension"}:
            require(reference_status == "ok", f"callable matrix projection row {index}.reference_status differs")
        elif comparison == "candidate-only-reviewed-project-c-abi-extension":
            require(reference_status == "not-in-pinned-inventory", f"callable matrix projection row {index}.reference_status differs")
        else:
            require(reference_status == "oracle-not-applicable", f"callable matrix projection row {index}.reference_status differs")
        key = (header, profile)
        require(key not in by_key, f"callable matrix projection repeats {header}:{profile}")
        by_key[key] = {"header": header, "profile": profile, "comparison": comparison, "reference_status": reference_status}
    return by_key, provenance


def _validate_partition(
    provider_names: Sequence[str],
    deferred: Mapping[str, Any],
    abi_only_callables: Sequence[Mapping[str, Any]],
) -> tuple[list[str], list[dict[str, Any]], list[dict[str, str]]]:
    require(isinstance(provider_names, Sequence) and not isinstance(provider_names, (str, bytes)), "selected callable provider names are invalid")
    providers = [symbol(name, "selected callable provider name") for name in provider_names]
    require(providers == sorted(providers) and len(providers) == len(set(providers)) and bool(providers), "selected callable provider roster differs")
    require(isinstance(deferred, Mapping), "deferred callable partition is invalid")
    deferred_rows: list[dict[str, Any]] = []
    for name in sorted(deferred):
        normalized_name = symbol(name, "deferred callable name")
        raw = exact_keys(
            deferred[name],
            {
                "id",
                "linkage_owner_family",
                "linkage_owner_obligation",
                "members",
                "provider_target",
                "resolution",
                "semantic_family",
                "source_oracle",
            },
            f"deferred callable {normalized_name}",
        )
        members = raw["members"]
        require(isinstance(members, list) and members == sorted(set(members)) and normalized_name in members, f"deferred callable {normalized_name} membership differs")
        for member in members:
            symbol(member, f"deferred callable {normalized_name} member")
        resolution = string(raw["resolution"], f"deferred callable {normalized_name}.resolution")
        require(resolution in DEFERRED_RESOLUTIONS, f"deferred callable {normalized_name}.resolution is unknown")
        deferred_rows.append(
            {
                "name": normalized_name,
                "id": string(raw["id"], f"deferred callable {normalized_name}.id"),
                "linkage_owner_family": string(raw["linkage_owner_family"], f"deferred callable {normalized_name}.linkage_owner_family"),
                "linkage_owner_obligation": string(raw["linkage_owner_obligation"], f"deferred callable {normalized_name}.linkage_owner_obligation"),
                "provider_target": string(raw["provider_target"], f"deferred callable {normalized_name}.provider_target"),
                "resolution": resolution,
                "semantic_family": string(raw["semantic_family"], f"deferred callable {normalized_name}.semantic_family"),
                "source_oracle": string(raw["source_oracle"], f"deferred callable {normalized_name}.source_oracle"),
            }
        )
    deferred_names = {item["name"] for item in deferred_rows}
    require(set(providers).isdisjoint(deferred_names), "provider and deferred callable partitions overlap")
    require(isinstance(abi_only_callables, Sequence) and not isinstance(abi_only_callables, (str, bytes)), "ABI-only callable partition is invalid")
    abi_only: list[dict[str, str]] = []
    names: set[str] = set()
    for index, raw_item in enumerate(abi_only_callables):
        raw = exact_keys(raw_item, {"name", "owner", "state", "runner"}, f"ABI-only callable {index}")
        name = symbol(raw["name"], f"ABI-only callable {index}.name")
        require(name not in names, f"ABI-only callable {name} is duplicated")
        names.add(name)
        abi_only.append(
            {
                "name": name,
                "owner": string(raw["owner"], f"ABI-only callable {name}.owner"),
                "state": string(raw["state"], f"ABI-only callable {name}.state"),
                "runner": string(raw["runner"], f"ABI-only callable {name}.runner"),
            }
        )
    require(not (set(providers) | deferred_names) & names, "ABI-only callable overlaps header callable partition")
    return providers, deferred_rows, sorted(abi_only, key=lambda item: item["name"])


def _header_envelope(value: Mapping[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any]]:
    raw = exact_keys(value, {"current_selecting_source", "report"}, "header declaration reader envelope")
    current = exact_keys(raw["current_selecting_source"], {"matches_retained", "differences"}, "header declaration current source")
    require(type(current["matches_retained"]) is bool and isinstance(current["differences"], list), "header declaration current source types differ")
    require(not current["matches_retained"] or not current["differences"], "current source match differs from differences")
    report = raw["report"]
    require(isinstance(report, Mapping) and set(report) == HEADER_REPORT_KEYS, "header declaration report keys changed")
    require(report.get("schema") == HEADER_REPORT_SCHEMA and report.get("target") == TARGET, "header declaration report identity differs")
    require(isinstance(report.get("occurrences"), list), "header declaration report occurrences are invalid")
    # The public reader authenticated and reconstructed all macro and raw
    # artifacts before this adapter receives the envelope.  Preserve their
    # schema presence, but never treat them as callable declarations.
    require(isinstance(report.get("macro_events"), list) and isinstance(report.get("final_active_macros"), list), "header declaration macro records are invalid")
    return {
        "matches_retained": current["matches_retained"],
        "differences": copy.deepcopy(current["differences"]),
    }, report


def _raw_function(raw: Mapping[str, Any], index: int, tree: str) -> dict[str, Any]:
    record = exact_keys(raw, RAW_FUNCTION_KEYS, f"raw callable occurrence {index}")
    require(record["kind"] == "function" and record["tree"] == tree, f"raw callable occurrence {index} kind/tree differs")
    name = symbol(record["name"], f"raw callable occurrence {index}.name")
    header = safe_relative(record["input_header"], f"raw callable occurrence {index}.input_header")
    profile = string(record["profile"], f"raw callable occurrence {index}.profile")
    require(profile in PROFILE_LANGUAGES, f"raw callable occurrence {index}.profile is unknown")
    require(record["source_language"] == PROFILE_LANGUAGES[profile], f"raw callable occurrence {index}.source_language differs")
    source = exact_keys(record["source"], RAW_SOURCE_KEYS, f"raw callable occurrence {index}.source")
    root = "candidate-header-root" if tree == "candidate" else "pinned-musl-header-root"
    require(source["include_root"] == root, f"raw callable occurrence {index}.source root differs")
    require(source["origin_resolution"] == "physical", f"raw callable occurrence {index}.source is not physical")
    checked_source = {
        "column": positive_integer(source["column"], f"raw callable occurrence {index}.source.column"),
        "declaring_header": safe_relative(source["declaring_header"], f"raw callable occurrence {index}.source.declaring_header"),
        "include_root": root,
        "line": positive_integer(source["line"], f"raw callable occurrence {index}.source.line"),
        "offset": positive_integer(source["offset"], f"raw callable occurrence {index}.source.offset", zero=True),
        "origin_resolution": "physical",
        "token_length": positive_integer(source["token_length"], f"raw callable occurrence {index}.source.token_length"),
    }
    type_record = exact_keys(record["type"], {"qual_type", "desugared_qual_type"}, f"raw callable occurrence {index}.type")
    qual_type = string(type_record["qual_type"], f"raw callable occurrence {index}.type.qual_type")
    desugared = type_record["desugared_qual_type"]
    require(desugared is None or isinstance(desugared, str) and bool(desugared), f"raw callable occurrence {index}.type.desugared_qual_type is invalid")
    linkage = record["linkage_specifier_languages"]
    require(isinstance(linkage, list) and all(isinstance(item, str) and item for item in linkage), f"raw callable occurrence {index}.linkage specifiers are invalid")
    require(record["storage_class_observation"] is None or isinstance(record["storage_class_observation"], str), f"raw callable occurrence {index}.storage class is invalid")
    require(record["tls_observation"] is None or type(record["tls_observation"]) is bool, f"raw callable occurrence {index}.TLS observation is invalid")
    require(isinstance(record["previous_declaration"], Mapping), f"raw callable occurrence {index}.previous declaration is invalid")
    require(isinstance(record["unmodeled_node_keys"], list) and all(isinstance(item, str) for item in record["unmodeled_node_keys"]), f"raw callable occurrence {index}.unmodeled keys are invalid")
    return {
        "occurrence_index": index,
        "ast_node_ordinal": positive_integer(record["ast_node_ordinal"], f"raw callable occurrence {index}.ast ordinal", zero=True),
        "occurrence_ordinal": positive_integer(record["occurrence_ordinal"], f"raw callable occurrence {index}.occurrence ordinal", zero=True),
        "name": name,
        "input_header": header,
        "profile": profile,
        "source_language": record["source_language"],
        "source": checked_source,
        "type": {"qual_type": qual_type, "desugared_qual_type": desugared},
        "mangled_name_observation": string(record["mangled_name_observation"], f"raw callable occurrence {index}.mangled name"),
        "linkage_status": string(record["linkage_status"], f"raw callable occurrence {index}.linkage status"),
        "linkage_specifier_languages": list(linkage),
        "storage_class_observation": record["storage_class_observation"],
        "definition_observation": string(record["definition_observation"], f"raw callable occurrence {index}.definition observation"),
        "tls_observation": record["tls_observation"],
        "previous_declaration": copy.deepcopy(dict(record["previous_declaration"])),
        "raw_ast_path": safe_relative(record["raw_ast_path"], f"raw callable occurrence {index}.raw AST path"),
        "raw_node_id_observation": string(record["raw_node_id_observation"], f"raw callable occurrence {index}.raw node id"),
        "unmodeled_node_keys": list(record["unmodeled_node_keys"]),
    }


def _signature_multiset(observations: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    values = Counter(
        f"{item['type']['qual_type']}|mangled={item['mangled_name_observation']}" for item in observations
    )
    return [{"signature": signature, "count": values[signature]} for signature in sorted(values)]


def _status_counts(observations: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    values = Counter(str(item["linkage_status"]) for item in observations)
    return dict(sorted(values.items()))


def _record_group(
    *,
    category: str,
    matrix_comparison: str,
    header: str,
    profile: str,
    name: str,
    candidate: Sequence[Mapping[str, Any]],
    reference: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "category": category,
        "matrix_comparison": matrix_comparison,
        "input_header": header,
        "profile": profile,
        "name": name,
        "candidate_observations": [copy.deepcopy(dict(item)) for item in candidate],
        "reference_observations": [copy.deepcopy(dict(item)) for item in reference],
        "candidate_signature_multiset": _signature_multiset(candidate),
        "reference_signature_multiset": _signature_multiset(reference),
        "raw_linkage_status_counts": {
            "candidate": _status_counts(candidate),
            "reference": _status_counts(reference),
        },
    }


def _reviewed_extension_groups(
    *,
    candidate_groups: Mapping[tuple[str, str, str], Sequence[Mapping[str, Any]]],
    reference_groups: Mapping[tuple[str, str, str], Sequence[Mapping[str, Any]]],
    matrix: Mapping[tuple[str, str], Mapping[str, str]],
    providers: set[str],
) -> tuple[list[dict[str, Any]], set[tuple[str, str, str]]]:
    try:
        extension_contract = callable_extension_contract.load_contract()
    except callable_extension_contract.CallableExtensionContractError as error:
        raise NativeCallableDeclarationsError(f"reviewed native callable extension contract is invalid: {error}") from error
    records: list[dict[str, Any]] = []
    consumed: set[tuple[str, str, str]] = set()
    for extension in extension_contract.extensions:
        require(extension.name in providers, f"reviewed native callable extension {extension.name} is not selected by the provider partition")
        expected = {
            (header, profile, extension.name)
            for header in extension.visible_from_headers
            for profile in extension.visible_profiles
        }
        observed = {key for key in candidate_groups if key[2] == extension.name}
        require(observed == expected, f"reviewed native callable extension {extension.name} visible raw roster differs")
        require(not {key for key in reference_groups if key[2] == extension.name}, f"reviewed native callable extension {extension.name} has a reference declaration")
        for header, profile, name in sorted(expected):
            matrix_row = matrix.get((header, profile))
            require(matrix_row is not None and matrix_row["comparison"] == "candidate-only-reviewed-native-callable-extension", f"reviewed native callable extension {name} matrix route differs: {header}:{profile}")
            candidate = candidate_groups[(header, profile, name)]
            require(len(candidate) == 1, f"reviewed native callable extension {name} raw multiplicity differs: {header}:{profile}")
            observation = candidate[0]
            require(observation["source"]["declaring_header"] == extension.header, f"reviewed native callable extension {name} physical header differs: {header}:{profile}")
            require(observation["type"]["qual_type"] == extension.signature, f"reviewed native callable extension {name} signature differs: {header}:{profile}")
            require(observation["mangled_name_observation"] == extension.c_linkage_symbol, f"reviewed native callable extension {name} linker spelling differs: {header}:{profile}")
            records.append(
                _record_group(
                    category="reviewed-native-extension",
                    matrix_comparison="candidate-only-reviewed-native-callable-extension",
                    header=header,
                    profile=profile,
                    name=name,
                    candidate=candidate,
                    reference=[],
                )
            )
            consumed.add((header, profile, name))
        hidden = [key for key in candidate_groups if key[2] == extension.name and key[1] in extension.hidden_profiles]
        require(not hidden, f"reviewed native callable extension {extension.name} is visible in a hidden profile")
    return records, consumed


def _deferred_account(
    occurrences: Sequence[Any],
    deferred: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    names = {item["name"] for item in deferred}
    by_name: dict[str, dict[str, list[dict[str, Any]]]] = {
        name: {"candidate": [], "reference": []} for name in names
    }
    for index, raw in enumerate(occurrences):
        if not isinstance(raw, Mapping) or raw.get("kind") != "function" or raw.get("name") not in names:
            continue
        tree = raw.get("tree")
        require(tree in {"candidate", "reference"}, f"deferred callable raw occurrence {index} tree differs")
        by_name[str(raw["name"])][tree].append(_raw_function(raw, index, tree))
    records: list[dict[str, Any]] = []
    for item in deferred:
        observations = by_name[item["name"]]
        present = bool(observations["candidate"] or observations["reference"])
        records.append(
            {
                **copy.deepcopy(dict(item)),
                "raw_function_declaration_status": "observed-but-deferred" if present else "not-observed-by-raw-function-inventory",
                "candidate_observations": observations["candidate"],
                "reference_observations": observations["reference"],
                "candidate_signature_multiset": _signature_multiset(observations["candidate"]),
                "reference_signature_multiset": _signature_multiset(observations["reference"]),
                "macro_or_legacy_fallback_status": "not-consumed-as-declaration-evidence",
                "provider_selection": "deferred-by-existing-disposition",
            }
        )
    return records


def account_declarations(
    header_report_envelope: Mapping[str, Any],
    *,
    provider_names: Sequence[str],
    deferred: Mapping[str, Any],
    abi_only_callables: Sequence[Mapping[str, Any]],
    matrix_projection: Mapping[str, Any],
    contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Account declaration forms using one already replayed header envelope.

    The caller owns authenticating that envelope and validating the full matrix
    before projecting it.  This function reuses those facts without a second
    reader/compiler invocation, preserves selected raw occurrence multiplicity,
    and deliberately leaves provider/linkage/runtime/family claims open.
    """
    _reviewed_contract(contract)
    current_source, report = _header_envelope(header_report_envelope)
    providers, deferred_rows, abi_only = _validate_partition(provider_names, deferred, abi_only_callables)
    matrix, matrix_provenance = _validate_matrix_projection(matrix_projection)
    provider_set = set(providers)
    candidate_groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    reference_groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for index, raw in enumerate(report["occurrences"]):
        if not isinstance(raw, Mapping) or raw.get("kind") != "function" or raw.get("name") not in provider_set:
            continue
        tree = raw.get("tree")
        require(tree in {"candidate", "reference"}, f"selected callable raw occurrence {index} tree differs")
        observation = _raw_function(raw, index, tree)
        key = (observation["input_header"], observation["profile"], observation["name"])
        require((key[0], key[1]) in matrix, f"selected callable raw occurrence has no checked matrix row: {key[0]}:{key[1]}")
        (candidate_groups if tree == "candidate" else reference_groups)[key].append(observation)
    observed_provider_names = {key[2] for key in candidate_groups}
    require(observed_provider_names == provider_set, "selected callable provider raw declaration roster differs")
    extension_records, extension_groups = _reviewed_extension_groups(
        candidate_groups=candidate_groups,
        reference_groups=reference_groups,
        matrix=matrix,
        providers=provider_set,
    )
    records: list[dict[str, Any]] = []
    consumed = set(extension_groups)
    for key in sorted(candidate_groups):
        if key in consumed:
            continue
        header, profile, name = key
        candidate = candidate_groups[key]
        reference = reference_groups.get(key, [])
        matrix_row = matrix[(header, profile)]
        comparison = matrix_row["comparison"]
        if comparison == "matched":
            require(bool(reference), f"reference-backed callable declaration is absent: {header}:{profile}:{name}")
            candidate_signatures = _signature_multiset(candidate)
            reference_signatures = _signature_multiset(reference)
            require(candidate_signatures == reference_signatures, f"callable declaration signature multiset differs: {header}:{profile}:{name}")
            records.append(_record_group(category="reference-backed", matrix_comparison=comparison, header=header, profile=profile, name=name, candidate=candidate, reference=reference))
        elif comparison == "candidate-only-reviewed-native-callable-extension":
            # A matrix row is reviewed because it contains the one exact
            # tgkill difference.  Its other functions still have ordinary
            # reference-backed observations and must not be relabeled as
            # candidate-only extensions merely by sharing that include row.
            require(bool(reference), f"reference-backed callable declaration is absent in reviewed extension row: {header}:{profile}:{name}")
            candidate_signatures = _signature_multiset(candidate)
            reference_signatures = _signature_multiset(reference)
            require(candidate_signatures == reference_signatures, f"callable declaration signature multiset differs in reviewed extension row: {header}:{profile}:{name}")
            records.append(_record_group(category="reference-backed", matrix_comparison=comparison, header=header, profile=profile, name=name, candidate=candidate, reference=reference))
        elif comparison == "candidate-only-reviewed-project-c-abi-extension":
            require(not reference, f"project-only callable unexpectedly has a reference declaration: {header}:{profile}:{name}")
            records.append(_record_group(category="candidate-project-extension", matrix_comparison=comparison, header=header, profile=profile, name=name, candidate=candidate, reference=[]))
        elif comparison == "oracle-not-applicable":
            require(not reference, f"oracle-not-applicable callable unexpectedly has a reference declaration: {header}:{profile}:{name}")
            records.append(_record_group(category="oracle-not-applicable", matrix_comparison=comparison, header=header, profile=profile, name=name, candidate=candidate, reference=[]))
        else:
            raise NativeCallableDeclarationsError(f"unreviewed native callable matrix route: {header}:{profile}:{name}")
    orphan_reference = sorted(set(reference_groups) - set(candidate_groups))
    if orphan_reference:
        raise NativeCallableDeclarationsError(
            f"reference callable declaration has no candidate group: {orphan_reference[0]}"
        )
    records.extend(extension_records)
    records.sort(key=lambda item: (item["input_header"], item["profile"], item["name"]))
    category_counts = Counter(item["category"] for item in records)
    candidate_count = sum(len(item["candidate_observations"]) for item in records)
    reference_count = sum(len(item["reference_observations"]) for item in records)
    source_match = current_source["matches_retained"]
    return {
        "schema": SCHEMA,
        "target": TARGET,
        "oracle": ORACLE,
        "header_declaration_report_schema": HEADER_REPORT_SCHEMA,
        "header_abi_matrix_report_schema": HEADER_MATRIX_REPORT_SCHEMA,
        "matrix_provenance": matrix_provenance,
        "source_receipt": {
            "current_selecting_source_matches_retained": source_match,
            "current_selecting_source_differences": current_source["differences"],
        },
        "selected_callable_declaration_status": (
            "proved-with-explicit-boundaries" if source_match else "historical-source-drift-with-explicit-boundaries"
        ),
        "scope": {
            "selected_provider_name_count": len(providers),
            "raw_candidate_function_occurrence_count": candidate_count,
            "raw_reference_function_occurrence_count": reference_count,
            "direct_header_profile_name_group_count": len(records),
            "category_counts": dict(sorted(category_counts.items())),
            "provider_selection": "not-evaluated",
            "semantic_language_linkage": "not-proved-by-clang-json",
            "desugared_qual_type": "retained-not-normalized-or-compared",
            "runtime": "not-evaluated",
            "family_completion": "not-claimed",
            "public_support": "not-claimed",
        },
        "groups": records,
        "deferred": _deferred_account(report["occurrences"], deferred_rows),
        "abi_only_callables": [
            {
                **item,
                "header_declaration_status": "not-consumed-by-callable-declaration-adapter",
                "provider_selection": "owned-by-separate-feature-abi-only-account",
            }
            for item in abi_only
        ],
    }
