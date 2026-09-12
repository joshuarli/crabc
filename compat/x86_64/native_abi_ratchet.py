#!/usr/bin/env python3
"""Check the reviewed x86 public-dynamic ABI regression floor.

This component consumes a fresh, publicly replayed native ABI inventory.  It
does not decide compatibility, complete a family, or promote a product.  The
tracked baseline is deliberately read-only reviewed policy; this tool has no
baseline-update command.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

import native_abi_inventory as inventory


BASELINE_SCHEMA = "crabc.x86_64-native-abi-dynamic-ratchet/v1"
CHECK_SCHEMA = "crabc.x86_64-native-abi-dynamic-ratchet-check/v1"
INVENTORY_SCHEMA = inventory.SCHEMA
TARGET = inventory.TARGET
BASELINE_PATH = ROOT / "compat/ratchet/x86_64-dynamic.json"
CHECK_REPORT_NAME = "ratchet.json"
ALLOWED_BINDINGS = frozenset({"GLOBAL", "WEAK", "UNIQUE"})
ALLOWED_VISIBILITIES = frozenset({"DEFAULT", "PROTECTED"})
SUPPORTED_TYPES = frozenset({"NOTYPE", "OBJECT", "FUNC", "TLS", "IFUNC"})
DATA_TYPES = frozenset({"OBJECT", "TLS"})
SYMBOL_RECORD_KEYS = frozenset(inventory.DYNAMIC_COLUMNS)
IDENTITY_KEYS = frozenset({"name", "version", "version_default"})
ABI_KEYS = frozenset({"type", "binding", "visibility", "data_size"})
POLICY_STATUS = {
    "classification": "monotonic-regression-floor-not-compatibility-or-promotion",
    "family_completion": False,
    "promotion_ready": False,
    "public_support": False,
}
_SHA256 = inventory._SHA256
_REVISION = inventory._REVISION


class RatchetError(RuntimeError):
    """A baseline, fresh inventory, or retained ratchet result drifted."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RatchetError(message)


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _stable_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _same_json(left: object, right: object) -> bool:
    """Compare retained JSON with type fidelity (JSON 0 is not JSON false)."""

    return _stable_json(left) == _stable_json(right)


def _read_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_object)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise RatchetError(f"{description} is not valid JSON: {path}") from error
    require(isinstance(value, dict), f"{description} must be a JSON object")
    return value


def _exact_mapping(value: object, keys: frozenset[str], description: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == keys, f"{description} fields drifted")
    return value


def _digest(value: object, description: str) -> str:
    require(isinstance(value, str) and _SHA256.fullmatch(value) is not None, f"{description} has invalid SHA-256")
    return value


def _identity_sort_key(identity: Mapping[str, object]) -> tuple[str, str, bool]:
    return (
        str(identity["name"]),
        "" if identity["version"] is None else str(identity["version"]),
        bool(identity["version_default"]),
    )


def _identity_from_record(record: Mapping[str, object]) -> dict[str, object]:
    name = record["name"]
    version = record["version"]
    version_default = record["version_default"]
    require(isinstance(name, str) and name, "public symbol name is malformed")
    require(version is None or (isinstance(version, str) and version), "public symbol version is malformed")
    require(type(version_default) is bool, "public symbol version defaultness is malformed")
    return {"name": name, "version": version, "version_default": version_default}


def _metadata_from_record(record: Mapping[str, object]) -> dict[str, object]:
    symbol_type = record["type"]
    binding = record["binding"]
    visibility = record["visibility"]
    size = record["size"]
    require(isinstance(symbol_type, str) and symbol_type in SUPPORTED_TYPES, f"unsupported public symbol type: {symbol_type!r}")
    require(isinstance(binding, str) and binding in ALLOWED_BINDINGS, f"unsupported public symbol binding: {binding!r}")
    require(isinstance(visibility, str) and visibility in ALLOWED_VISIBILITIES, f"unsupported public symbol visibility: {visibility!r}")
    require(isinstance(size, str) and size, "public symbol size is malformed")
    return {
        "type": symbol_type,
        "binding": binding,
        "visibility": visibility,
        "data_size": size if symbol_type in DATA_TYPES else None,
    }


def _symbol_entry(record: object) -> dict[str, object]:
    record = _exact_mapping(record, SYMBOL_RECORD_KEYS, "inventory dynamic symbol")
    value = record["value"]
    section_index = record["section_index"]
    require(isinstance(value, str) and value, "public symbol value is malformed")
    require(isinstance(section_index, str) and section_index, "public symbol section index is malformed")
    return {
        "identity": _identity_from_record(record),
        "abi": _metadata_from_record(record),
    }


def _validated_symbol_entries(entries: object, description: str) -> list[dict[str, object]]:
    require(isinstance(entries, list), f"{description} must be a list")
    normalized: list[dict[str, object]] = []
    seen: set[tuple[str, str | None, bool]] = set()
    for entry in entries:
        entry = _exact_mapping(entry, frozenset({"identity", "abi"}), description)
        identity = _exact_mapping(entry["identity"], IDENTITY_KEYS, f"{description} identity")
        abi = _exact_mapping(entry["abi"], ABI_KEYS, f"{description} ABI")
        normalized_entry = {
            "identity": _identity_from_record({
                "name": identity["name"],
                "version": identity["version"],
                "version_default": identity["version_default"],
            }),
            "abi": {
                "type": abi["type"],
                "binding": abi["binding"],
                "visibility": abi["visibility"],
                "data_size": abi["data_size"],
            },
        }
        # Reuse the raw-record checks without inventing an alternate public
        # vocabulary.  Value and section stay in the inventory, not the floor.
        synthetic = {
            "name": normalized_entry["identity"]["name"],
            "version": normalized_entry["identity"]["version"],
            "version_default": normalized_entry["identity"]["version_default"],
            "type": normalized_entry["abi"]["type"],
            "binding": normalized_entry["abi"]["binding"],
            "visibility": normalized_entry["abi"]["visibility"],
            "size": normalized_entry["abi"]["data_size"] or "0",
            "value": "0",
            "section_index": "0",
        }
        actual_abi = _metadata_from_record(synthetic)
        if normalized_entry["abi"]["type"] not in DATA_TYPES:
            require(normalized_entry["abi"]["data_size"] is None, f"{description} function data size is not null")
        else:
            require(
                isinstance(normalized_entry["abi"]["data_size"], str) and normalized_entry["abi"]["data_size"],
                f"{description} data size is malformed",
            )
        require(actual_abi == normalized_entry["abi"], f"{description} ABI is malformed")
        key = (
            str(normalized_entry["identity"]["name"]),
            normalized_entry["identity"]["version"],
            bool(normalized_entry["identity"]["version_default"]),
        )
        require(key not in seen, f"{description} repeats a symbol identity")
        seen.add(key)
        normalized.append(normalized_entry)
    return sorted(normalized, key=lambda entry: _identity_sort_key(entry["identity"]))


def symbol_state(records: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Reduce complete inventory rows to the explicit ratchet ABI surface."""

    entries = [_symbol_entry(record) for record in records]
    entries = _validated_symbol_entries(entries, "symbol state")
    return {"symbols": entries}


def _state_entries(state: object, description: str) -> list[dict[str, object]]:
    state = _exact_mapping(state, frozenset({"symbols"}), description)
    return _validated_symbol_entries(state["symbols"], f"{description} symbols")


def _entry_map(entries: Sequence[Mapping[str, object]]) -> dict[tuple[str, str | None, bool], dict[str, object]]:
    result: dict[tuple[str, str | None, bool], dict[str, object]] = {}
    for entry in entries:
        identity = entry["identity"]
        require(isinstance(identity, dict), "symbol identity state is malformed")
        key = (str(identity["name"]), identity["version"], bool(identity["version_default"]))
        require(key not in result, "symbol identity repeats")
        result[key] = dict(entry)
    return result


def _identities(keys: Sequence[tuple[str, str | None, bool]]) -> list[dict[str, object]]:
    return [
        {"name": name, "version": version, "version_default": version_default}
        for name, version, version_default in sorted(keys, key=lambda key: (key[0], "" if key[1] is None else key[1], key[2]))
    ]


def _ratcheted_fields(expected: Mapping[str, object]) -> tuple[str, ...]:
    """Return the ABI fields controlled by the pinned expected symbol type.

    A candidate that calls an expected function an OBJECT still retains its raw
    object size in the underlying inventory.  That size cannot become a second
    independent policy failure: the expected function has no data-layout
    field.  Conversely, expected OBJECT and TLS entries bind their size even
    while another metadata field is wrong.
    """

    fields = ("type", "binding", "visibility")
    return fields + (("data_size",) if expected["type"] in DATA_TYPES else ())


def _incorrect_fields(expected: Mapping[str, object], candidate: Mapping[str, object]) -> list[str]:
    return [field for field in _ratcheted_fields(expected) if candidate[field] != expected[field]]


def comparison_state(
    reference_entries: Sequence[Mapping[str, object]],
    candidate_entries: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    expected = _entry_map(reference_entries)
    candidate = _entry_map(candidate_entries)
    expected_keys = set(expected)
    candidate_keys = set(candidate)
    mismatched: list[dict[str, object]] = []
    matched: list[tuple[str, str | None, bool]] = []
    for key in sorted(expected_keys & candidate_keys, key=lambda item: (item[0], "" if item[1] is None else item[1], item[2])):
        incorrect = _incorrect_fields(expected[key]["abi"], candidate[key]["abi"])
        if incorrect:
            mismatched.append({
                "identity": dict(expected[key]["identity"]),
                "expected": dict(expected[key]["abi"]),
                "candidate": dict(candidate[key]["abi"]),
                "incorrect_fields": incorrect,
            })
        else:
            matched.append(key)
    return {
        "missing": _identities(list(expected_keys - candidate_keys)),
        "unexpected": _identities(list(candidate_keys - expected_keys)),
        "matched": _identities(matched),
        "mismatched": mismatched,
    }


def _file_identity(path: Path, description: str) -> dict[str, object]:
    try:
        path = inventory.physical_regular(path, description)
        details = path.lstat()
        return {
            "path": str(path),
            "sha256": inventory.sha256(path),
            "size": details.st_size,
            "mode": stat.S_IMODE(details.st_mode),
        }
    except inventory.InventoryError as error:
        raise RatchetError(f"{description} is invalid: {error}") from error


def _validate_file_identity(value: object, description: str) -> dict[str, object]:
    value = _exact_mapping(value, frozenset({"path", "sha256", "size", "mode"}), description)
    require(isinstance(value["path"], str) and value["path"].startswith("/"), f"{description} path is malformed")
    _digest(value["sha256"], description)
    require(type(value["size"]) is int and value["size"] >= 0, f"{description} size is malformed")
    require(type(value["mode"]) is int and 0 <= value["mode"] <= 0o7777, f"{description} mode is malformed")
    return dict(value)


def _validate_execution_source(value: object, description: str) -> dict[str, object]:
    value = _exact_mapping(value, frozenset({"revision", "content_sha256", "clean"}), description)
    require(isinstance(value["revision"], str) and _REVISION.fullmatch(value["revision"]) is not None, f"{description} revision is malformed")
    _digest(value["content_sha256"], description)
    require(value["clean"] is True, f"{description} is not clean")
    return dict(value)


def _validate_policy_status(value: object, description: str) -> dict[str, object]:
    value = _exact_mapping(value, frozenset(POLICY_STATUS), description)
    require(
        value["classification"] == POLICY_STATUS["classification"],
        f"{description} classification drifted",
    )
    for field in ("family_completion", "promotion_ready", "public_support"):
        require(type(value[field]) is bool, f"{description} {field} is not boolean")
        require(value[field] is False, f"{description} {field} drifted")
    return dict(POLICY_STATUS)


def _validate_review_record(value: object) -> dict[str, object]:
    value = _exact_mapping(value, frozenset({"path", "sha256", "size"}), "baseline review record")
    require(isinstance(value["path"], str) and value["path"].startswith("/"), "baseline review path is malformed")
    _digest(value["sha256"], "baseline review record")
    require(type(value["size"]) is int and value["size"] > 0, "baseline review size is malformed")
    return dict(value)


def _validate_inventory_report_origin(value: object, description: str) -> dict[str, object]:
    report = _exact_mapping(
        value,
        frozenset({"path", "sha256", "size", "schema", "target", "image", "collector_execution_source"}),
        description,
    )
    require(
        isinstance(report["path"], str) and report["path"].startswith("/"),
        f"{description} path is malformed",
    )
    _digest(report["sha256"], description)
    require(type(report["size"]) is int and report["size"] > 0, f"{description} size is malformed")
    require(report["schema"] == INVENTORY_SCHEMA and report["target"] == TARGET, f"{description} contract drifted")
    require(isinstance(report["image"], str) and inventory._IMAGE.fullmatch(report["image"]) is not None, f"{description} image is malformed")
    report["collector_execution_source"] = _validate_execution_source(
        report["collector_execution_source"], f"{description} collector source"
    )
    return report


def _validate_oracle_origin(value: object, description: str) -> dict[str, object]:
    oracle = _exact_mapping(value, frozenset({"repository_pin", "shared_identity"}), description)
    pin = _exact_mapping(
        oracle["repository_pin"],
        frozenset({"version", "source", "sha256", "fallback_repository", "fallback_revision"}),
        f"{description} repository pin",
    )
    require(pin["version"] == "1.2.6", f"{description} version drifted")
    for field in ("source", "fallback_repository"):
        require(isinstance(pin[field], str) and pin[field], f"{description} {field} is malformed")
    _digest(pin["sha256"], f"{description} source")
    require(
        isinstance(pin["fallback_revision"], str) and _REVISION.fullmatch(pin["fallback_revision"]) is not None,
        f"{description} fallback revision is malformed",
    )
    oracle["shared_identity"] = _validate_file_identity(oracle["shared_identity"], f"{description} shared identity")
    return oracle


def _validate_candidate_origin(value: object, description: str) -> dict[str, object]:
    candidate = _exact_mapping(
        value,
        frozenset({"build", "shared_identity", "dynamic_manifest_sha256"}),
        description,
    )
    build = _exact_mapping(
        candidate["build"],
        frozenset({"classification", "revision", "source_content_sha256", "revision_provenance"}),
        f"{description} build",
    )
    require(
        build["classification"] == "materialized-unqualified-product-measurement-only",
        f"{description} build classification drifted",
    )
    require(
        isinstance(build["revision"], str) and _REVISION.fullmatch(build["revision"]) is not None,
        f"{description} build revision is malformed",
    )
    _digest(build["source_content_sha256"], f"{description} source")
    require(isinstance(build["revision_provenance"], str) and build["revision_provenance"], f"{description} provenance is malformed")
    candidate["shared_identity"] = _validate_file_identity(candidate["shared_identity"], f"{description} shared identity")
    _digest(candidate["dynamic_manifest_sha256"], f"{description} dynamic manifest")
    return candidate


def _validate_origin(origin: object) -> dict[str, object]:
    origin = _exact_mapping(origin, frozenset({"inventory_report", "review", "oracle", "candidate"}), "baseline origin")
    return {
        "inventory_report": _validate_inventory_report_origin(
            origin["inventory_report"], "baseline origin inventory report"
        ),
        "review": _validate_review_record(origin["review"]),
        "oracle": _validate_oracle_origin(origin["oracle"], "baseline oracle origin"),
        "candidate": _validate_candidate_origin(origin["candidate"], "baseline candidate origin"),
    }


def baseline_from_symbol_sets(
    reference: Sequence[Mapping[str, object]],
    candidate: Sequence[Mapping[str, object]],
    *,
    origin: Mapping[str, object],
) -> dict[str, object]:
    reference_state = symbol_state(reference)
    candidate_state = symbol_state(candidate)
    baseline = {
        "schema": BASELINE_SCHEMA,
        "target": TARGET,
        "status": dict(POLICY_STATUS),
        "origin": dict(origin),
        "oracle_symbols": reference_state["symbols"],
        "baseline_candidate_symbols": candidate_state["symbols"],
        "baseline_state": comparison_state(reference_state["symbols"], candidate_state["symbols"]),
    }
    validate_baseline(baseline)
    return baseline


def validate_baseline(value: object) -> dict[str, object]:
    baseline = _exact_mapping(
        value,
        frozenset({
            "schema", "target", "status", "origin", "oracle_symbols",
            "baseline_candidate_symbols", "baseline_state",
        }),
        "native x86 dynamic ABI baseline",
    )
    require(baseline["schema"] == BASELINE_SCHEMA, "native x86 dynamic ABI baseline schema drifted")
    require(baseline["target"] == TARGET, "native x86 dynamic ABI baseline target drifted")
    status = _validate_policy_status(baseline["status"], "native x86 dynamic ABI baseline status")
    origin = _validate_origin(baseline["origin"])
    reference = _validated_symbol_entries(baseline["oracle_symbols"], "baseline oracle symbols")
    candidate = _validated_symbol_entries(baseline["baseline_candidate_symbols"], "baseline candidate symbols")
    require(reference, "baseline oracle symbols are empty")
    expected_state = comparison_state(reference, candidate)
    require(_same_json(baseline["baseline_state"], expected_state), "baseline state does not reconstruct its symbol sets")
    return {
        "schema": BASELINE_SCHEMA,
        "target": TARGET,
        "status": status,
        "origin": origin,
        "oracle_symbols": reference,
        "baseline_candidate_symbols": candidate,
        "baseline_state": expected_state,
    }


def _baseline(path: Path | None = None) -> tuple[dict[str, object], dict[str, object]]:
    if path is None:
        path = BASELINE_PATH
    try:
        path = inventory.physical_regular(path, "native x86 dynamic ABI baseline")
    except inventory.InventoryError as error:
        raise RatchetError(f"native x86 dynamic ABI baseline is invalid: {error}") from error
    return validate_baseline(_read_json(path, "native x86 dynamic ABI baseline")), _file_identity(path, "native x86 dynamic ABI baseline")


def evaluate(baseline: Mapping[str, object], current: Mapping[str, object]) -> dict[str, object]:
    """Apply the fieldwise monotonic policy to one fresh candidate surface."""

    baseline = validate_baseline(baseline)
    current_entries = _state_entries(current, "current candidate symbol state")
    expected_entries = baseline["oracle_symbols"]
    baseline_entries = baseline["baseline_candidate_symbols"]
    require(isinstance(expected_entries, list) and isinstance(baseline_entries, list), "validated baseline symbol state drifted")
    expected = _entry_map(expected_entries)
    old = _entry_map(baseline_entries)
    now = _entry_map(current_entries)
    expected_keys = set(expected)
    old_keys = set(old)
    now_keys = set(now)
    baseline_missing = expected_keys - old_keys
    current_missing = expected_keys - now_keys
    baseline_extras = old_keys - expected_keys
    current_extras = now_keys - expected_keys
    baseline_matches = {
        key
        for key in expected_keys & old_keys
        if not _incorrect_fields(expected[key]["abi"], old[key]["abi"])
    }
    baseline_mismatches = (expected_keys & old_keys) - baseline_matches

    newly_present_not_correct: list[tuple[str, str | None, bool]] = []
    resolved_missing: list[tuple[str, str | None, bool]] = []
    for key in sorted(baseline_missing & now_keys, key=lambda item: (item[0], "" if item[1] is None else item[1], item[2])):
        if _incorrect_fields(expected[key]["abi"], now[key]["abi"]):
            newly_present_not_correct.append(key)
        else:
            resolved_missing.append(key)

    regressed_matches: list[tuple[str, str | None, bool]] = []
    for key in sorted(baseline_matches, key=lambda item: (item[0], "" if item[1] is None else item[1], item[2])):
        if key not in now or _incorrect_fields(expected[key]["abi"], now[key]["abi"]):
            regressed_matches.append(key)

    field_transitions: list[dict[str, object]] = []
    corrected_fields: list[dict[str, object]] = []
    for key in sorted(baseline_mismatches & now_keys, key=lambda item: (item[0], "" if item[1] is None else item[1], item[2])):
        improved: list[str] = []
        for field in _ratcheted_fields(expected[key]["abi"]):
            old_value = old[key]["abi"][field]
            expected_value = expected[key]["abi"][field]
            current_value = now[key]["abi"][field]
            if current_value not in {old_value, expected_value}:
                field_transitions.append({
                    "symbol": dict(expected[key]["identity"]),
                    "field": field,
                    "baseline": old_value,
                    "expected": expected_value,
                    "current": current_value,
                })
            elif old_value != expected_value and current_value == expected_value:
                improved.append(field)
        if improved:
            corrected_fields.append({"symbol": dict(expected[key]["identity"]), "fields": improved})

    return {
        "current": comparison_state(expected_entries, current_entries),
        "violations": {
            "new_missing": _identities(list(current_missing - baseline_missing)),
            "new_unexpected": _identities(list(current_extras - baseline_extras)),
            "newly_present_not_correct": _identities(newly_present_not_correct),
            "regressed_matches": _identities(regressed_matches),
            "field_transitions": field_transitions,
        },
        "improvements": {
            "resolved_missing": _identities(resolved_missing),
            "removed_unexpected": _identities(list(baseline_extras - current_extras)),
            "corrected_fields": corrected_fields,
        },
    }


def _inventory_origin(report: Mapping[str, object], report_path: Path) -> dict[str, object]:
    try:
        inputs = report["inputs"]
        inventories = report["inventories"]
        provenance = report["product_provenance"]
        pinned_musl = inputs["pinned_musl"]
        reference = inventories["reference"]["shared"]
        candidate = inventories["candidate"]["shared"]
        materialization = provenance["dynamic_materialization"]
        build = provenance["candidate_build"]
    except (KeyError, TypeError) as error:
        raise RatchetError("public inventory report lacks ratchet provenance") from error
    require(report["schema"] == INVENTORY_SCHEMA and report["target"] == TARGET, "public inventory report contract drifted")
    file_identity = _file_identity(report_path, "public inventory report")
    report_identity = {
        field: file_identity[field]
        for field in ("path", "sha256", "size")
    }
    return {
        "inventory_report": _validate_inventory_report_origin({
            **report_identity,
            "schema": report["schema"],
            "target": report["target"],
            "image": report["image"],
            "collector_execution_source": report["collector_execution_source"],
        }, "fresh inventory report"),
        "oracle": _validate_oracle_origin({
            "repository_pin": pinned_musl["repository_pin"],
            "shared_identity": reference["identity"],
        }, "fresh oracle origin"),
        "candidate": _validate_candidate_origin({
            "build": build,
            "shared_identity": candidate["identity"],
            "dynamic_manifest_sha256": materialization["manifest_sha256"],
        }, "fresh candidate origin"),
    }


def _inventory_symbol_sets(report: Mapping[str, object]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    try:
        reference = report["inventories"]["reference"]["shared"]["dynamic_symbols"]
        candidate = report["inventories"]["candidate"]["shared"]["dynamic_symbols"]
    except (KeyError, TypeError) as error:
        raise RatchetError("public inventory report lacks shared dynamic symbols") from error
    require(isinstance(reference, list) and isinstance(candidate, list), "public inventory dynamic symbol rows are malformed")
    return _state_entries(symbol_state(reference), "public reference symbols"), _state_entries(symbol_state(candidate), "public candidate symbols")


def _validate_fresh_inventory(
    inventory_report: Path,
    *,
    static_product: Path,
    dynamic_product: Path,
    static_preparation: Path,
) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]], list[dict[str, object]]]:
    try:
        report = inventory.validate_report(
            inventory_report,
            static_product=static_product,
            dynamic_product=dynamic_product,
            static_preparation=static_preparation,
        )
        source = inventory.collector_source_seal()
    except inventory.InventoryError as error:
        raise RatchetError(f"public native ABI inventory validation failed: {error}") from error
    require(report["collector_execution_source"] == source, "fresh inventory collector source differs from ratchet source")
    origin = _inventory_origin(report, inventory_report)
    reference, candidate = _inventory_symbol_sets(report)
    return report, origin, reference, candidate


def _verify_oracle_floor(baseline: Mapping[str, object], current_origin: Mapping[str, object], reference: Sequence[Mapping[str, object]]) -> None:
    baseline_origin = baseline["origin"]
    require(isinstance(baseline_origin, dict), "validated baseline origin drifted")
    require(current_origin["oracle"] == baseline_origin["oracle"], "pinned musl oracle identity differs from reviewed ratchet baseline")
    require(list(reference) == baseline["oracle_symbols"], "pinned musl public ABI surface differs from reviewed ratchet baseline")


def _check_payload(
    inventory_report: Path,
    *,
    static_product: Path,
    dynamic_product: Path,
    static_preparation: Path,
) -> dict[str, object]:
    baseline, baseline_identity = _baseline()
    report, current_origin, reference, candidate = _validate_fresh_inventory(
        inventory_report,
        static_product=static_product,
        dynamic_product=dynamic_product,
        static_preparation=static_preparation,
    )
    _verify_oracle_floor(baseline, current_origin, reference)
    result = evaluate(baseline, {"symbols": candidate})
    violations = result["violations"]
    require(isinstance(violations, dict), "ratchet violation state is malformed")
    return {
        "schema": CHECK_SCHEMA,
        "status": dict(POLICY_STATUS),
        "baseline": {
            "path": str(BASELINE_PATH.relative_to(ROOT)),
            "identity": baseline_identity,
        },
        "ratchet_execution_source": inventory.collector_source_seal(),
        "inventory_report": current_origin["inventory_report"],
        "current_oracle": current_origin["oracle"],
        "current_candidate": current_origin["candidate"],
        "current": result["current"],
        "violations": violations,
        "improvements": result["improvements"],
        "passed": not any(violations.values()),
    }


def _work_output(path: Path, description: str) -> Path:
    path = Path(os.path.abspath(path))
    work_root = ROOT / ".work/x86_64"
    try:
        require(path.is_relative_to(work_root), f"{description} is outside this checkout's .work/x86_64")
        require(not path.exists(), f"{description} already exists")
        parent = inventory.physical_directory(path.parent, f"{description} parent")
        require(parent == path.parent, f"{description} parent is not physical")
        path.mkdir(mode=0o700)
        return path
    except inventory.InventoryError as error:
        raise RatchetError(f"{description} is invalid: {error}") from error
    except OSError as error:
        raise RatchetError(f"cannot create {description}: {path}") from error


def _write_private(path: Path, value: object) -> None:
    try:
        path.write_bytes(_stable_json(value))
        path.chmod(0o600)
    except OSError as error:
        raise RatchetError(f"cannot write ratchet output: {path}") from error


def check(
    inventory_report: Path,
    *,
    static_product: Path,
    dynamic_product: Path,
    static_preparation: Path,
    output: Path,
) -> Path:
    payload = _check_payload(
        inventory_report,
        static_product=static_product,
        dynamic_product=dynamic_product,
        static_preparation=static_preparation,
    )
    root = _work_output(output, "native ABI ratchet output")
    report = root / CHECK_REPORT_NAME
    _write_private(report, payload)
    return report


def validate_check_report(
    report_path: Path,
    *,
    inventory_report: Path,
    static_product: Path,
    dynamic_product: Path,
    static_preparation: Path,
) -> dict[str, object]:
    try:
        report_path = inventory.physical_regular(report_path, "native ABI ratchet report")
    except inventory.InventoryError as error:
        raise RatchetError(f"native ABI ratchet report is invalid: {error}") from error
    require(report_path.name == CHECK_REPORT_NAME, "native ABI ratchet report has the wrong name")
    retained = _read_json(report_path, "native ABI ratchet report")
    expected = _check_payload(
        inventory_report,
        static_product=static_product,
        dynamic_product=dynamic_product,
        static_preparation=static_preparation,
    )
    require(
        _same_json(retained, expected),
        "native ABI ratchet report does not reconstruct current baseline and inventory",
    )
    return retained


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)

    def inputs(command: argparse.ArgumentParser) -> None:
        command.add_argument("--inventory-report", type=Path, required=True)
        command.add_argument("--static-product", type=Path, required=True)
        command.add_argument("--dynamic-product", type=Path, required=True)
        command.add_argument("--static-preparation", type=Path, required=True)

    check_parser = subcommands.add_parser("check", help="validate a fresh inventory and write one ratchet result")
    inputs(check_parser)
    check_parser.add_argument("--output", type=Path, required=True)

    replay_parser = subcommands.add_parser("validate-report", help="purely replay one retained ratchet result")
    replay_parser.add_argument("report", type=Path)
    inputs(replay_parser)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        if arguments.action == "check":
            path = check(
                arguments.inventory_report,
                static_product=arguments.static_product,
                dynamic_product=arguments.dynamic_product,
                static_preparation=arguments.static_preparation,
                output=arguments.output,
            )
            print(path)
            return 0 if _read_json(path, "native ABI ratchet report")["passed"] is True else 1
        else:
            retained = validate_check_report(
                arguments.report,
                inventory_report=arguments.inventory_report,
                static_product=arguments.static_product,
                dynamic_product=arguments.dynamic_product,
                static_preparation=arguments.static_preparation,
            )
            print(arguments.report)
            return 0 if retained["passed"] is True else 1
        return 0
    except RatchetError as error:
        print(f"native ABI ratchet error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
