#!/usr/bin/env python3
"""Account selected native public-data header declarations without selecting providers.

This adapter consumes the envelope already replayed by
``header_declaration_inventory.validate_report``.  It does not invoke Clang,
parse C text, choose an ELF provider, infer C++ linkage from mangled spelling,
or evaluate object/record layout.  The reviewed TOML names the finite selected
object contracts and their direct installed-header/profile requirements.
"""
from __future__ import annotations

import copy
from pathlib import Path
import tomllib
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "native_data_declarations.toml"
SCHEMA = "crabc.x86_64-native-data-declarations/v1"
HEADER_REPORT_SCHEMA = "crabc.x86_64-header-declaration-inventory/v1"
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
PROFILE_SET_NAMES = {
    "all",
    "xopen_gnu_bsd",
    "posix_xopen_gnu_bsd",
    "gnu_effective",
    "gnu_bsd_effective",
}
EXPECTED_OBJECTS = (
    ("object:___environ", "___environ", "abi-only"),
    ("object:__daylight", "__daylight", "abi-only"),
    ("object:__environ", "__environ", "abi-only"),
    ("object:__optpos", "__optpos", "abi-only"),
    ("object:__optreset", "__optreset", "abi-only"),
    ("object:__progname", "__progname", "abi-only"),
    ("object:__progname_full", "__progname_full", "abi-only"),
    ("object:__signgam", "__signgam", "abi-only"),
    ("object:__stack_chk_guard", "__stack_chk_guard", "abi-only"),
    ("object:__timezone", "__timezone", "abi-only"),
    ("object:__tzname", "__tzname", "abi-only"),
    ("object:_dl_debug_addr", "_dl_debug_addr", "abi-only"),
    ("object:_environ", "_environ", "abi-only"),
    ("object:_ns_flagdata", "_ns_flagdata", "installed-variable"),
    ("object:daylight", "daylight", "installed-variable"),
    ("object:environ", "environ", "installed-variable"),
    ("object:getdate_err", "getdate_err", "installed-variable"),
    ("object:h_errno", "h_errno", "accessor-macro"),
    ("object:in6addr_any", "in6addr_any", "installed-variable"),
    ("object:in6addr_loopback", "in6addr_loopback", "installed-variable"),
    ("object:optarg", "optarg", "installed-variable"),
    ("object:opterr", "opterr", "installed-variable"),
    ("object:optind", "optind", "installed-variable"),
    ("object:optopt", "optopt", "installed-variable"),
    ("object:optreset", "optreset", "installed-variable"),
    ("object:program_invocation_name", "program_invocation_name", "installed-variable"),
    ("object:program_invocation_short_name", "program_invocation_short_name", "installed-variable"),
    ("object:signgam", "signgam", "installed-variable"),
    ("object:stderr", "stderr", "installed-variable"),
    ("object:stdin", "stdin", "installed-variable"),
    ("object:stdout", "stdout", "installed-variable"),
    ("object:timezone", "timezone", "installed-variable"),
    ("object:tzname", "tzname", "installed-variable"),
)
EXPECTED_OBJECT_IDS = tuple(item[0] for item in EXPECTED_OBJECTS)
EXPECTED_OBJECT_BY_ID = {item[0]: {"name": item[1], "declaration_kind": item[2]} for item in EXPECTED_OBJECTS}


class NativeDataDeclarationsError(ValueError):
    """The selected public-data declaration contract is malformed or differs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeDataDeclarationsError(message)


def exact_keys(value: object, keys: set[str], description: str) -> Mapping[str, Any]:
    require(isinstance(value, Mapping) and set(value) == keys, f"{description} fields differ")
    return value


def string(value: object, description: str, *, empty: bool = False) -> str:
    require(isinstance(value, str) and (empty or bool(value)), f"{description} is not a string")
    return value


def boolean(value: object, description: str) -> bool:
    require(type(value) is bool, f"{description} is not Boolean")
    return value


def integer(value: object, description: str) -> int:
    require(type(value) is int and value > 0, f"{description} is not a positive integer")
    return value


def strings(value: object, description: str, *, empty: bool = False) -> list[str]:
    require(isinstance(value, list) and (empty or bool(value)), f"{description} is not a nonempty list")
    result = [string(item, description) for item in value]
    require(len(result) == len(set(result)), f"{description} contains duplicates")
    return result


def safe_header(value: object, description: str) -> str:
    result = string(value, description)
    path = Path(result)
    require(not path.is_absolute() and ".." not in path.parts and path.as_posix() == result, f"{description} is not a header-relative path")
    return result


def _load_toml(path: Path) -> Mapping[str, Any]:
    try:
        with path.open("rb") as stream:
            result = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise NativeDataDeclarationsError(f"cannot load {path}: {error}") from error
    require(isinstance(result, Mapping), "native data declaration contract is not a table")
    return result


def _validate_profile_sets(value: object) -> dict[str, list[str]]:
    raw = exact_keys(value, PROFILE_SET_NAMES, "native data declaration profile sets")
    result: dict[str, list[str]] = {}
    for identifier in sorted(PROFILE_SET_NAMES):
        profiles = strings(raw[identifier], f"profile set {identifier}")
        require(set(profiles) <= set(PROFILE_LANGUAGES), f"profile set {identifier} has an unknown profile")
        result[identifier] = profiles
    require(result["all"] == list(PROFILE_LANGUAGES), "profile set all differs from the finite profile roster")
    return result


def _common_object_fields(raw: Mapping[str, Any], expected_keys: set[str], description: str) -> dict[str, Any]:
    exact_keys(raw, expected_keys, description)
    identifier = string(raw["id"], f"{description}.id")
    name = string(raw["name"], f"{description}.name")
    kind = raw["declaration_kind"]
    require(kind in {"installed-variable", "accessor-macro", "abi-only"}, f"{description}.declaration_kind is invalid")
    declaration = string(raw["declaration"], f"{description}.declaration")
    c_abi_type = string(raw["c_abi_type"], f"{description}.c_abi_type")
    mutable = boolean(raw["source_mutable"], f"{description}.source_mutable")
    expected = EXPECTED_OBJECT_BY_ID.get(identifier)
    require(expected is not None, f"{description} has an unselected object id")
    require(expected == {"name": name, "declaration_kind": kind}, f"{description} identity differs from selected object contract")
    return {
        "id": identifier,
        "name": name,
        "declaration_kind": kind,
        "declaration": declaration,
        "c_abi_type": c_abi_type,
        "source_mutable": mutable,
    }


def _validate_site(raw: object, profile_sets: Mapping[str, Sequence[str]], description: str) -> dict[str, Any]:
    item = exact_keys(raw, {"header", "candidate_line", "reference_line", "profile_set"}, description)
    header = safe_header(item["header"], f"{description}.header")
    candidate_line = integer(item["candidate_line"], f"{description}.candidate_line")
    reference_line = integer(item["reference_line"], f"{description}.reference_line")
    profile_set = string(item["profile_set"], f"{description}.profile_set")
    require(profile_set in profile_sets, f"{description}.profile_set is unknown")
    return {
        "header": header,
        "candidate_line": candidate_line,
        "reference_line": reference_line,
        "profile_set": profile_set,
        "profiles": list(profile_sets[profile_set]),
    }


def _validate_installed_object(raw: Mapping[str, Any], profile_sets: Mapping[str, Sequence[str]], index: int) -> dict[str, Any]:
    keys = {
        "id", "name", "declaration_kind", "declaration", "c_abi_type", "source_mutable", "header_storage_kind",
        "qual_type", "object_qualifier", "pointer_target_mutability", "array_extent", "layout_evidence", "sites",
    }
    result = _common_object_fields(raw, keys, f"installed data object {index}")
    require(result["declaration_kind"] == "installed-variable", f"installed data object {result['name']} kind differs")
    require(raw["header_storage_kind"] == "installed-variable", f"{result['name']} header storage kind differs")
    result["header_storage_kind"] = "installed-variable"
    result["qual_type"] = string(raw["qual_type"], f"{result['name']} qual_type")
    result["object_qualifier"] = string(raw["object_qualifier"], f"{result['name']} object qualifier")
    result["pointer_target_mutability"] = string(raw["pointer_target_mutability"], f"{result['name']} pointer target mutability")
    result["array_extent"] = string(raw["array_extent"], f"{result['name']} array extent")
    require(raw["layout_evidence"] == "not-proved-by-declaration-inventory", f"{result['name']} layout evidence differs")
    result["layout_evidence"] = raw["layout_evidence"]
    sites = raw["sites"]
    require(isinstance(sites, list) and sites, f"{result['name']} sites are absent")
    result["sites"] = [_validate_site(site, profile_sets, f"{result['name']} site {site_index}") for site_index, site in enumerate(sites)]
    headers = [site["header"] for site in result["sites"]]
    require(len(headers) == len(set(headers)), f"{result['name']} repeats a physical header site")
    return result


def _validate_accessor_object(raw: Mapping[str, Any], index: int) -> dict[str, Any]:
    keys = {
        "id", "name", "declaration_kind", "declaration", "c_abi_type", "source_mutable", "header_storage_kind",
        "macro_header", "macro_candidate_line", "macro_reference_line", "macro_profiles", "macro_form", "macro_replacement",
        "accessor_name", "accessor_header", "accessor_candidate_line", "accessor_reference_line", "accessor_qual_types",
        "accessor_storage_class", "accessor_linkage_status", "accessor_definition_observation",
    }
    result = _common_object_fields(raw, keys, f"accessor macro object {index}")
    require(result["declaration_kind"] == "accessor-macro", f"accessor macro object {result['name']} kind differs")
    require(raw["header_storage_kind"] == "accessor-macro-not-object", f"{result['name']} header storage kind differs")
    result["header_storage_kind"] = raw["header_storage_kind"]
    result["macro_header"] = safe_header(raw["macro_header"], f"{result['name']} macro header")
    result["macro_candidate_line"] = integer(raw["macro_candidate_line"], f"{result['name']} macro candidate line")
    result["macro_reference_line"] = integer(raw["macro_reference_line"], f"{result['name']} macro reference line")
    result["macro_profiles"] = strings(raw["macro_profiles"], f"{result['name']} macro profiles")
    require(set(result["macro_profiles"]) <= set(PROFILE_LANGUAGES), f"{result['name']} macro profile is unknown")
    result["macro_form"] = string(raw["macro_form"], f"{result['name']} macro form")
    require(result["macro_form"] == "object-like", f"{result['name']} macro form differs")
    result["macro_replacement"] = string(raw["macro_replacement"], f"{result['name']} macro replacement", empty=True)
    result["accessor_name"] = string(raw["accessor_name"], f"{result['name']} accessor name")
    result["accessor_header"] = safe_header(raw["accessor_header"], f"{result['name']} accessor header")
    result["accessor_candidate_line"] = integer(raw["accessor_candidate_line"], f"{result['name']} accessor candidate line")
    result["accessor_reference_line"] = integer(raw["accessor_reference_line"], f"{result['name']} accessor reference line")
    types = exact_keys(raw["accessor_qual_types"], {"c", "cxx"}, f"{result['name']} accessor type map")
    result["accessor_qual_types"] = {language: string(types[language], f"{result['name']} accessor {language} type") for language in ("c", "cxx")}
    require(raw["accessor_storage_class"] == "none", f"{result['name']} accessor storage observation differs")
    result["accessor_storage_class"] = None
    require(raw["accessor_linkage_status"] == "unresolved-from-json", f"{result['name']} accessor linkage status differs")
    result["accessor_linkage_status"] = raw["accessor_linkage_status"]
    require(raw["accessor_definition_observation"] == "unresolved-from-json", f"{result['name']} accessor definition observation differs")
    result["accessor_definition_observation"] = raw["accessor_definition_observation"]
    return result


def _validate_abi_only_object(raw: Mapping[str, Any], index: int) -> dict[str, Any]:
    keys = {"id", "name", "declaration_kind", "declaration", "c_abi_type", "source_mutable", "header_storage_kind", "absence_scope"}
    result = _common_object_fields(raw, keys, f"ABI-only data object {index}")
    require(result["declaration_kind"] == "abi-only", f"ABI-only data object {result['name']} kind differs")
    require(raw["header_storage_kind"] == "abi-only-absence", f"{result['name']} header storage kind differs")
    require(raw["absence_scope"] == "finite-header-declaration-inventory", f"{result['name']} absence scope differs")
    result["header_storage_kind"] = raw["header_storage_kind"]
    result["absence_scope"] = raw["absence_scope"]
    return result


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    """Load the reviewed selected-data declaration/profile contract strictly."""
    raw = exact_keys(
        _load_toml(path),
        {"schema", "target", "oracle", "header_declaration_report_schema", "profile_languages", "profile_sets", "objects"},
        "native data declaration contract",
    )
    require(raw["schema"] == SCHEMA, "native data declaration contract schema differs")
    require(raw["target"] == TARGET, "native data declaration contract target differs")
    require(raw["oracle"] == ORACLE, "native data declaration contract oracle differs")
    require(raw["header_declaration_report_schema"] == HEADER_REPORT_SCHEMA, "native data declaration report schema differs")
    languages = exact_keys(raw["profile_languages"], set(PROFILE_LANGUAGES), "native data declaration profile languages")
    require(dict(languages) == PROFILE_LANGUAGES, "native data declaration profile languages differ")
    profile_sets = _validate_profile_sets(raw["profile_sets"])
    objects_raw = raw["objects"]
    require(isinstance(objects_raw, list) and len(objects_raw) == len(EXPECTED_OBJECTS), "native data declaration object roster count differs")
    objects: list[dict[str, Any]] = []
    for index, raw_object in enumerate(objects_raw):
        require(isinstance(raw_object, Mapping), f"native data declaration object {index} is invalid")
        kind = raw_object.get("declaration_kind")
        if kind == "installed-variable":
            item = _validate_installed_object(raw_object, profile_sets, index)
        elif kind == "accessor-macro":
            item = _validate_accessor_object(raw_object, index)
        elif kind == "abi-only":
            item = _validate_abi_only_object(raw_object, index)
        else:
            raise NativeDataDeclarationsError(f"native data declaration object {index} kind is invalid")
        objects.append(item)
    require(tuple(item["id"] for item in objects) == EXPECTED_OBJECT_IDS, "native data declaration object order or roster differs")
    return {
        "schema": SCHEMA,
        "target": TARGET,
        "oracle": ORACLE,
        "header_declaration_report_schema": HEADER_REPORT_SCHEMA,
        "profile_languages": copy.deepcopy(PROFILE_LANGUAGES),
        "profile_sets": copy.deepcopy(profile_sets),
        "objects": objects,
    }


def validate_selected_object_contracts(
    selected_objects: Sequence[Mapping[str, Any]],
    contract: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Bind exactly the 33 selected object contracts to reviewed declaration rows.

    The caller supplies selection's exact object-contract records.  Only the
    declaration-facing fields are consumed here; ELF placement and provider
    ownership remain selection's separate responsibilities.
    """
    if contract is None:
        contract = load_contract()
    require(isinstance(contract, Mapping), "native data declaration contract is invalid")
    contract_objects = contract.get("objects")
    require(isinstance(contract_objects, list), "native data declaration contract objects are invalid")
    require(isinstance(selected_objects, Sequence) and not isinstance(selected_objects, (str, bytes)), "selected object contracts are invalid")
    require(len(selected_objects) == len(contract_objects), "selected object contract roster count differs")
    expected = {item["id"]: item for item in contract_objects}
    selected: dict[str, Mapping[str, Any]] = {}
    for index, raw in enumerate(selected_objects):
        require(isinstance(raw, Mapping), f"selected object contract {index} is invalid")
        identifier = string(raw.get("id"), f"selected object contract {index}.id")
        require(identifier not in selected, f"selected object contract {identifier} is duplicated")
        selected[identifier] = raw
    require(set(selected) == set(expected), "selected object contract roster differs")
    normalized: list[dict[str, Any]] = []
    for identifier in EXPECTED_OBJECT_IDS:
        supplied = selected[identifier]
        reviewed = expected[identifier]
        for field in ("name", "declaration_kind", "declaration", "c_abi_type", "source_mutable"):
            require(field in supplied, f"selected object contract {identifier} lacks {field}")
            if field == "source_mutable":
                boolean(supplied[field], f"selected object contract {identifier}.{field}")
            else:
                string(supplied[field], f"selected object contract {identifier}.{field}")
            require(supplied[field] == reviewed[field], f"selected object contract {identifier} {field} differs")
        normalized.append(copy.deepcopy(reviewed))
    return normalized


def _report_envelope(envelope: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    exact_keys(envelope, {"current_selecting_source", "report"}, "replayed header declaration envelope")
    current = exact_keys(envelope["current_selecting_source"], {"matches_retained", "differences"}, "replayed header current source")
    boolean(current["matches_retained"], "replayed header current source match")
    require(isinstance(current["differences"], list), "replayed header current source differences are invalid")
    report = envelope["report"]
    require(isinstance(report, Mapping), "replayed header declaration report is invalid")
    require(report.get("schema") == HEADER_REPORT_SCHEMA, "replayed header declaration report schema differs")
    require(report.get("target") == TARGET, "replayed header declaration report target differs")
    scope = report.get("scope")
    require(isinstance(scope, Mapping), "replayed header declaration report scope is invalid")
    required_scope = {
        "compiler_ast_json": True,
        "compiler_preprocessor_records": True,
        "header_text_parsing": False,
        "layout_evaluation": False,
        "macro_events_before_collapse": True,
        "provider_selection": False,
        "runtime": False,
        "variable_occurrences_before_collapse": True,
    }
    for field, expected in required_scope.items():
        require(scope.get(field) is expected, f"replayed header declaration report scope {field} differs")
    for field in ("occurrences", "macro_events", "final_active_macros"):
        require(isinstance(report.get(field), list), f"replayed header declaration report {field} is invalid")
    return current, report


def _source(record: Mapping[str, Any], description: str) -> Mapping[str, Any]:
    source = record.get("source")
    require(isinstance(source, Mapping), f"{description} source is invalid")
    for field in ("declaring_header", "include_root", "origin_resolution"):
        string(source.get(field), f"{description} source {field}")
    integer(source.get("line"), f"{description} source line")
    return source


def _type(record: Mapping[str, Any], description: str) -> Mapping[str, Any]:
    value = record.get("type")
    require(isinstance(value, Mapping), f"{description} type is invalid")
    string(value.get("qual_type"), f"{description} qual_type")
    desugared = value.get("desugared_qual_type")
    require(desugared is None or isinstance(desugared, str) and bool(desugared), f"{description} desugared type is invalid")
    return value


def _source_matches(
    record: Mapping[str, Any],
    *,
    tree: str,
    root: str,
    header: str,
    line: int,
    description: str,
) -> None:
    require(record.get("tree") == tree, f"{description} tree differs")
    require(record.get("input_header") == header, f"{description} direct input header differs")
    source = _source(record, description)
    require(source["include_root"] == root, f"{description} source root differs")
    require(source["declaring_header"] == header, f"{description} physical header differs")
    require(source["line"] == line, f"{description} source line differs")
    require(source["origin_resolution"] == "physical", f"{description} source resolution differs")


def _linkage_and_name(
    record: Mapping[str, Any],
    *,
    name: str,
    language: str,
    linkage_status: str,
    storage: str | None,
    definition: str,
    description: str,
) -> None:
    require(record.get("source_language") == language, f"{description} source language differs")
    require(record.get("mangled_name_observation") == name, f"{description} {'C++ ' if language == 'cxx' else ''}linker name differs")
    require(record.get("linkage_status") == linkage_status, f"{description} linkage status differs")
    require(record.get("storage_class_observation") == storage, f"{description} storage observation differs")
    require(record.get("definition_observation") == definition, f"{description} definition observation differs")
    require(record.get("tls_observation") is None, f"{description} TLS observation differs")
    linkage = record.get("linkage_specifier_languages")
    require(isinstance(linkage, list) and all(isinstance(item, str) and item for item in linkage), f"{description} linkage specifier context is invalid")
    if language == "c":
        require(linkage == [], f"{description} C linkage context differs")
    else:
        require(bool(linkage) and all(item == "C" for item in linkage), f"{description} C++ language linkage differs")


def _direct_variable_records(
    occurrences: Sequence[Any],
    item: Mapping[str, Any],
    *,
    tree: str,
) -> list[Mapping[str, Any]]:
    root = "candidate-header-root" if tree == "candidate" else "pinned-musl-header-root"
    headers = {site["header"] for site in item["sites"]}
    named: list[Mapping[str, Any]] = []
    direct: list[Mapping[str, Any]] = []
    for ordinal, raw in enumerate(occurrences):
        if not isinstance(raw, Mapping) or raw.get("tree") != tree or raw.get("name") != item["name"]:
            continue
        require(raw.get("kind") == "variable", f"{item['name']} has a non-variable declaration occurrence")
        source = _source(raw, f"{item['name']} occurrence {ordinal}")
        require(source["include_root"] == root, f"{item['name']} occurrence source root differs")
        require(source["declaring_header"] in headers, f"{item['name']} physical declaration header differs")
        named.append(raw)
        if raw.get("input_header") == source["declaring_header"]:
            direct.append(raw)
    return direct


def _validate_variable_object(occurrences: Sequence[Any], item: Mapping[str, Any]) -> dict[str, Any]:
    expected: dict[tuple[str, str], Mapping[str, Any]] = {}
    for site in item["sites"]:
        for profile in site["profiles"]:
            key = (site["header"], profile)
            require(key not in expected, f"{item['name']} direct declaration profile is duplicated in the contract")
            expected[key] = site
    desugared: dict[str, list[str | None]] = {}
    evidence_counts: dict[str, int] = {}
    for tree in ("candidate", "reference"):
        direct = _direct_variable_records(occurrences, item, tree=tree)
        seen: dict[tuple[str, str], Mapping[str, Any]] = {}
        for record in direct:
            header = record.get("input_header")
            profile = record.get("profile")
            require(isinstance(header, str) and isinstance(profile, str), f"{item['name']} direct declaration identity is invalid")
            key = (header, profile)
            require(key not in seen, f"{item['name']} direct declaration repeats {header}:{profile}")
            seen[key] = record
        require(set(seen) == set(expected), f"{item['name']} direct declaration profile roster differs")
        values: list[str | None] = []
        for key, site in expected.items():
            record = seen[key]
            line = site["candidate_line"] if tree == "candidate" else site["reference_line"]
            _source_matches(
                record,
                tree=tree,
                root="candidate-header-root" if tree == "candidate" else "pinned-musl-header-root",
                header=site["header"],
                line=line,
                description=f"{item['name']} direct declaration",
            )
            type_info = _type(record, f"{item['name']} direct declaration")
            require(type_info["qual_type"] == item["qual_type"], f"{item['name']} declaration type differs")
            values.append(type_info["desugared_qual_type"])
            language = PROFILE_LANGUAGES[key[1]]
            _linkage_and_name(
                record,
                name=item["name"],
                language=language,
                linkage_status="source-external-declaration",
                storage="extern",
                definition="extern-declaration-without-initializer",
                description=f"{item['name']} direct declaration",
            )
        desugared[tree] = sorted(values, key=lambda value: "" if value is None else value)
        evidence_counts[tree] = len(direct)
    return {
        "id": item["id"],
        "name": item["name"],
        "declaration_kind": item["declaration_kind"],
        "header_storage_kind": item["header_storage_kind"],
        "qual_type": item["qual_type"],
        "desugared_qual_type_observation": desugared,
        "source_mutable": item["source_mutable"],
        "object_qualifier": item["object_qualifier"],
        "pointer_target_mutability": item["pointer_target_mutability"],
        "array_extent": item["array_extent"],
        "layout_evidence": item["layout_evidence"],
        "direct_header_profile_occurrence_counts": evidence_counts,
        "proof": {
            "candidate_reference_declaration_agreement": "proved-against-reviewed-direct-rules",
            "direct_header_profile": "proved",
            "qualified_type": "proved",
            "linker_name": "proved",
            "language_linkage": "proved",
            "storage_and_tls": "proved",
            "object_layout": "not-evaluated-by-declaration-inventory",
            "provider_selection": "not-evaluated",
            "runtime": "not-evaluated",
        },
    }


def _macro_source_matches(
    record: Mapping[str, Any],
    item: Mapping[str, Any],
    *,
    tree: str,
    line_key: str,
    description: str,
) -> None:
    root = "candidate-header-root" if tree == "candidate" else "pinned-musl-header-root"
    require(record.get("tree") == tree, f"{description} tree differs")
    require(record.get("input_header") == item["macro_header"], f"{description} direct input header differs")
    source = _source(record, description)
    require(source["include_root"] == root, f"{description} source root differs")
    require(source["declaring_header"] == item["macro_header"], f"{description} physical header differs")
    require(source["line"] == item[line_key], f"{description} source line differs")
    require(source["origin_resolution"] == "physical", f"{description} source resolution differs")
    require(record.get("form") == item["macro_form"], f"{description} form differs")
    require(record.get("replacement") == item["macro_replacement"], f"{description} replacement differs")


def _direct_macro_records(records: Sequence[Any], item: Mapping[str, Any], *, tree: str, description: str) -> list[Mapping[str, Any]]:
    root = "candidate-header-root" if tree == "candidate" else "pinned-musl-header-root"
    direct: list[Mapping[str, Any]] = []
    for ordinal, raw in enumerate(records):
        if not isinstance(raw, Mapping) or raw.get("tree") != tree or raw.get("name") != item["name"]:
            continue
        source = _source(raw, f"{description} {ordinal}")
        require(source["include_root"] == root, f"{description} source root differs")
        require(source["declaring_header"] == item["macro_header"], f"{description} physical header differs")
        if raw.get("input_header") == item["macro_header"]:
            direct.append(raw)
    return direct


def _validate_h_errno(occurrences: Sequence[Any], macro_events: Sequence[Any], active: Sequence[Any], item: Mapping[str, Any]) -> dict[str, Any]:
    for tree in ("candidate", "reference"):
        for raw in occurrences:
            if isinstance(raw, Mapping) and raw.get("tree") == tree and raw.get("name") == item["name"]:
                raise NativeDataDeclarationsError(f"{item['name']} accessor macro is reclassified as a header declaration")
    expected_profiles = set(item["macro_profiles"])
    counts: dict[str, dict[str, int]] = {}
    for field, records in (("macro event", macro_events), ("final macro", active)):
        for tree in ("candidate", "reference"):
            direct = _direct_macro_records(records, item, tree=tree, description=f"{item['name']} {field}")
            by_profile: dict[str, Mapping[str, Any]] = {}
            for record in direct:
                profile = record.get("profile")
                require(isinstance(profile, str), f"{item['name']} {field} profile is invalid")
                require(profile not in by_profile, f"{item['name']} {field} repeats profile {profile}")
                by_profile[profile] = record
            require(set(by_profile) == expected_profiles, f"{item['name']} {'final ' if field == 'final macro' else ''}macro profile roster differs")
            for profile, record in by_profile.items():
                require(profile in PROFILE_LANGUAGES, f"{item['name']} {field} profile is unknown")
                if field == "macro event":
                    require(record.get("event") == "define", f"{item['name']} macro event differs")
                _macro_source_matches(
                    record,
                    item,
                    tree=tree,
                    line_key="macro_candidate_line" if tree == "candidate" else "macro_reference_line",
                    description=f"{item['name']} {field}",
                )
            counts.setdefault(tree, {})[field] = len(direct)
    accessor_counts: dict[str, int] = {}
    for tree in ("candidate", "reference"):
        root = "candidate-header-root" if tree == "candidate" else "pinned-musl-header-root"
        direct: list[Mapping[str, Any]] = []
        for ordinal, raw in enumerate(occurrences):
            if not isinstance(raw, Mapping) or raw.get("tree") != tree or raw.get("name") != item["accessor_name"]:
                continue
            require(raw.get("kind") == "function", f"{item['name']} accessor is not a function declaration")
            source = _source(raw, f"{item['name']} accessor {ordinal}")
            require(source["include_root"] == root, f"{item['name']} accessor source root differs")
            require(source["declaring_header"] == item["accessor_header"], f"{item['name']} accessor physical header differs")
            if raw.get("input_header") == item["accessor_header"]:
                direct.append(raw)
        by_profile: dict[str, Mapping[str, Any]] = {}
        for record in direct:
            profile = record.get("profile")
            require(isinstance(profile, str), f"{item['name']} accessor profile is invalid")
            require(profile not in by_profile, f"{item['name']} accessor repeats profile {profile}")
            by_profile[profile] = record
        require(set(by_profile) == expected_profiles, f"{item['name']} accessor profile roster differs")
        for profile, record in by_profile.items():
            language = PROFILE_LANGUAGES[profile]
            _source_matches(
                record,
                tree=tree,
                root=root,
                header=item["accessor_header"],
                line=item["accessor_candidate_line"] if tree == "candidate" else item["accessor_reference_line"],
                description=f"{item['name']} accessor",
            )
            type_info = _type(record, f"{item['name']} accessor")
            require(type_info["qual_type"] == item["accessor_qual_types"][language], f"{item['name']} accessor type differs")
            _linkage_and_name(
                record,
                name=item["accessor_name"],
                language=language,
                linkage_status=item["accessor_linkage_status"],
                storage=item["accessor_storage_class"],
                definition=item["accessor_definition_observation"],
                description=f"{item['name']} accessor",
            )
        accessor_counts[tree] = len(direct)
    return {
        "id": item["id"],
        "name": item["name"],
        "declaration_kind": item["declaration_kind"],
        "header_storage_kind": item["header_storage_kind"],
        "source_mutable": item["source_mutable"],
        "macro_header": item["macro_header"],
        "macro_profiles": list(item["macro_profiles"]),
        "macro_replacement": item["macro_replacement"],
        "accessor_name": item["accessor_name"],
        "accessor_qual_types": copy.deepcopy(item["accessor_qual_types"]),
        "accessor_linkage_status": item["accessor_linkage_status"],
        "macro_direct_occurrence_counts": counts,
        "accessor_direct_occurrence_counts": accessor_counts,
        "proof": {
            "macro_profile_and_expansion": "proved",
            "header_storage_kind": "proved-accessor-macro-not-object",
            "accessor_qualified_type": "proved",
            "accessor_linker_name": "proved",
            "accessor_language_linkage": "proved-where-clang-recorded-linkage-context",
            "accessor_linkage_status": "unresolved-from-json",
            "accessor_runtime_storage": "not-proved-by-declaration-inventory",
            "provider_selection": "not-evaluated",
            "runtime": "not-evaluated",
        },
    }


def _validate_abi_only(occurrences: Sequence[Any], macro_events: Sequence[Any], active: Sequence[Any], item: Mapping[str, Any]) -> dict[str, Any]:
    for label, records in (("header declaration", occurrences), ("macro event", macro_events), ("final active macro", active)):
        for raw in records:
            if isinstance(raw, Mapping) and raw.get("name") == item["name"] and raw.get("tree") in {"candidate", "reference"}:
                raise NativeDataDeclarationsError(f"{item['name']} ABI-only name appears as a {label}")
    return {
        "id": item["id"],
        "name": item["name"],
        "declaration_kind": item["declaration_kind"],
        "header_storage_kind": item["header_storage_kind"],
        "absence_scope": item["absence_scope"],
        "source_mutable": item["source_mutable"],
        "proof": {
            "header_absence": "proved-for-finite-header-profile-roster",
            "qualified_type": "not-applicable-header-absent",
            "language_linkage": "not-applicable-header-absent",
            "object_layout": "not-evaluated-by-declaration-inventory",
            "provider_selection": "not-evaluated",
            "runtime": "not-evaluated",
        },
    }


def account_declarations(
    header_report_envelope: Mapping[str, Any],
    selected_objects: Sequence[Mapping[str, Any]],
    *,
    contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Account the selected 19 + 1 + 13 declaration obligations.

    ``header_report_envelope`` must be the result already returned by the
    public declaration-inventory host replay.  This function consumes only its
    retained raw-derived facts; it does not re-run that replay or a compiler.
    A valid result is deliberately scoped to public-data header declarations.
    """
    if contract is None:
        contract = load_contract()
    reviewed = validate_selected_object_contracts(selected_objects, contract)
    current, report = _report_envelope(header_report_envelope)
    occurrences = report["occurrences"]
    macro_events = report["macro_events"]
    active = report["final_active_macros"]
    objects: list[dict[str, Any]] = []
    for item in reviewed:
        if item["declaration_kind"] == "installed-variable":
            objects.append(_validate_variable_object(occurrences, item))
        elif item["declaration_kind"] == "accessor-macro":
            objects.append(_validate_h_errno(occurrences, macro_events, active, item))
        else:
            objects.append(_validate_abi_only(occurrences, macro_events, active, item))
    source_match = current["matches_retained"]
    return {
        "schema": SCHEMA,
        "target": TARGET,
        "oracle": ORACLE,
        "header_declaration_report_schema": HEADER_REPORT_SCHEMA,
        "source_receipt": {
            "current_selecting_source_matches_retained": source_match,
            "current_selecting_source_differences": copy.deepcopy(current["differences"]),
        },
        "selected_data_declaration_status": (
            "proved-with-explicit-boundaries" if source_match else "historical-source-drift-with-explicit-boundaries"
        ),
        "scope": {
            "selected_object_contracts": len(objects),
            "installed_variables": sum(item["declaration_kind"] == "installed-variable" for item in objects),
            "accessor_macros": sum(item["declaration_kind"] == "accessor-macro" for item in objects),
            "abi_only_names": sum(item["declaration_kind"] == "abi-only" for item in objects),
            "provider_selection": "not-evaluated",
            "object_layout": "not-evaluated",
            "runtime": "not-evaluated",
            "family_completion": "not-claimed",
            "public_support": "not-claimed",
        },
        "objects": objects,
    }
