#!/usr/bin/env python3
"""Derive finite x86 declaration/macro feature visibility from checked ABI data.

``header_abi_matrix.py`` owns the one compiler-derived direct-public-include
collection pass. This smaller matrix consumes that checked report and compares
only named identities: ``(kind, name)`` for functions, typedefs, records,
enums, variables, and macros. A same-name source-form difference is therefore
still visible on both sides here and remains explicitly accounted by the source
declaration-form matrix rather than being misclassified as either a missing
feature or ABI equality.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MODULE_DIRECTORY = ROOT / "compat" / "x86_64"
if str(MODULE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(MODULE_DIRECTORY))

import header_abi_matrix
import header_callable_visibility_matrix as callable_visibility_matrix


CONTRACT_PATH = MODULE_DIRECTORY / "header_declaration_macro_visibility_matrix.toml"
SCHEMA = "crabc.x86_64-header-declaration-macro-feature-visibility-matrix-report/v1"
CONTRACT_SCHEMA = "crabc.x86_64-header-declaration-macro-feature-visibility-matrix/v1"
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
PROJECT_ONLY_HEADERS = (
    "daemon.h",
    "dn_expand.h",
    "linux/capability.h",
    "lrand48.h",
    "pthread_atfork.h",
    "stdatomic.h",
    "strverscmp.h",
    "sys/module.h",
)
FACT_KINDS = header_abi_matrix.FACT_KINDS
POLICY = {
    "derived_from_checked_declaration_form_matrix": True,
    "compiler_derived_source": True,
    "header_text_parsing": False,
    "direct_public_include_visibility": True,
    "named_declaration_and_macro_identity": True,
    "declaration_form_equality": False,
    "record_byte_layouts": False,
    "archive_linkage": False,
    "runtime": False,
    "family_promotion": False,
    "public_support": False,
}
WORK_PACKAGE_KEYS = {
    "target_family",
    "target_obligations",
    "blocker",
    "prerequisites",
    "dependent_work",
    "baseline_contract",
    "source_owners",
    "focused_evidence_command",
    "family_aggregate_command",
    "product_command",
    "negative_scope",
    "expected_transition",
    "evidence",
}


class HeaderDeclarationMacroVisibilityMatrixError(ValueError):
    """The finite declaration/macro visibility contract is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HeaderDeclarationMacroVisibilityMatrixError(message)


@dataclass(frozen=True)
class MatrixContract:
    """Trusted finite inputs for the derived all-header identity report."""

    source_abi_contract: Path
    source_abi_report: Path
    callable_visibility_contract: Path
    public_headers: Path
    generated_report: Path
    profiles: tuple[str, ...]
    project_only_headers: tuple[str, ...]
    oracle_not_applicable: Mapping[tuple[str, str], str]
    work_package: Mapping[str, Any]


def repository_path(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty path")
    relative = Path(value)
    require(not relative.is_absolute() and ".." not in relative.parts, f"{location} escapes the repository")
    result = ROOT / relative
    require(result.is_file() and not result.is_symlink(), f"{location} is not a regular repository file: {value}")
    return result


def repository_destination(value: object, location: str) -> Path:
    require(isinstance(value, str) and value, f"{location} must be a nonempty path")
    relative = Path(value)
    require(not relative.is_absolute() and ".." not in relative.parts, f"{location} escapes the repository")
    result = ROOT / relative
    parent = result.parent
    while parent != ROOT and not parent.exists():
        parent = parent.parent
    require(parent.is_dir() and not parent.is_symlink(), f"{location} parent is unsafe: {relative.parent}")
    return result


def string_list(value: object, location: str, *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{location} must be an array")
    result: list[str] = []
    for index, item in enumerate(value):
        require(isinstance(item, str) and item, f"{location}[{index}] is invalid")
        result.append(item)
    require(allow_empty or bool(result), f"{location} must not be empty")
    require(len(result) == len(set(result)), f"{location} has duplicates")
    return result


def load_contract(path: Path = CONTRACT_PATH) -> MatrixContract:
    """Load and cross-check all reviewed inputs before deriving a report."""

    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise HeaderDeclarationMacroVisibilityMatrixError(
            f"cannot load {path.relative_to(ROOT)}: {error}"
        ) from error
    require(isinstance(raw, Mapping), "declaration/macro visibility contract must be a table")
    expected_keys = {
        "schema",
        "target",
        "platform",
        "oracle",
        "source_abi_contract",
        "source_abi_report",
        "callable_visibility_contract",
        "public_headers",
        "generated_report",
        "pinned_public_header_count",
        "candidate_public_header_count",
        "profiles",
        "policy",
        "work_package",
        "oracle_not_applicable",
    }
    require(set(raw) == expected_keys, "declaration/macro visibility contract keys changed")
    require(raw["schema"] == CONTRACT_SCHEMA, "declaration/macro visibility contract schema changed")
    require(raw["target"] == TARGET, "declaration/macro visibility target changed")
    require(raw["platform"] == PLATFORM, "declaration/macro visibility platform changed")
    require(raw["oracle"] == ORACLE, "declaration/macro visibility oracle changed")
    require(raw["policy"] == POLICY, "declaration/macro visibility policy changed")
    require(raw["pinned_public_header_count"] == 183, "declaration/macro visibility pinned header count changed")
    require(raw["candidate_public_header_count"] == 191, "declaration/macro visibility candidate header count changed")

    source_abi_contract_path = repository_path(raw["source_abi_contract"], "source_abi_contract")
    source_abi_report = repository_path(raw["source_abi_report"], "source_abi_report")
    callable_visibility_contract_path = repository_path(
        raw["callable_visibility_contract"], "callable_visibility_contract"
    )
    public_headers = repository_path(raw["public_headers"], "public_headers")
    generated_report = repository_destination(raw["generated_report"], "generated_report")
    abi_contract = header_abi_matrix.load_contract()
    callable_contract = callable_visibility_matrix.load_contract()
    require(
        source_abi_contract_path == header_abi_matrix.CONTRACT_PATH
        and source_abi_report == abi_contract.generated_report,
        "declaration/macro visibility source ABI paths drifted",
    )
    require(
        callable_visibility_contract_path == callable_visibility_matrix.CONTRACT_PATH,
        "declaration/macro visibility callable policy contract drifted",
    )
    require(
        public_headers == abi_contract.public_headers == callable_contract.public_headers,
        "declaration/macro visibility public header inventory drifted",
    )
    profiles = tuple(string_list(raw["profiles"], "profiles"))
    require(profiles == PROFILES, "declaration/macro visibility profile order changed")
    require(
        profiles == tuple(profile.identifier for profile in abi_contract.profiles) == callable_contract.profiles,
        "declaration/macro visibility profile source drifted",
    )
    project_only_headers = tuple(header.path for header in callable_contract.project_only_headers)
    require(project_only_headers == PROJECT_ONLY_HEADERS, "declaration/macro visibility project-only paths drifted")

    work_package = raw["work_package"]
    require(isinstance(work_package, Mapping), "declaration/macro visibility work package is invalid")
    require(set(work_package) == WORK_PACKAGE_KEYS, "declaration/macro visibility work package keys changed")
    require(work_package["target_family"] == "libc.headers-layouts", "declaration/macro visibility family drifted")
    require(
        string_list(work_package["target_obligations"], "work_package.target_obligations")
        == ["feature-visibility"],
        "declaration/macro visibility obligation order changed",
    )
    require(
        string_list(work_package["prerequisites"], "work_package.prerequisites")
        == ["oracle.musl-toolchain", "libc.errno-tls"],
        "declaration/macro visibility prerequisite order changed",
    )
    for field in (
        "blocker",
        "baseline_contract",
        "focused_evidence_command",
        "family_aggregate_command",
        "product_command",
        "negative_scope",
        "expected_transition",
    ):
        require(
            isinstance(work_package[field], str) and work_package[field],
            f"work_package.{field} is invalid",
        )
    require(
        work_package["focused_evidence_command"]
        == "./scripts/dev-x86_64.sh header-declaration-macro-visibility-matrix",
        "declaration/macro visibility focused command drifted",
    )
    require(
        work_package["family_aggregate_command"]
        == "./scripts/dev-x86_64.sh campaign-family libc.headers-layouts",
        "declaration/macro visibility aggregate command drifted",
    )
    require(
        string_list(work_package["evidence"], "work_package.evidence")
        == ["all-header-declaration-macro-feature-visibility-matrix"],
        "declaration/macro visibility evidence identifier drifted",
    )
    string_list(work_package["dependent_work"], "work_package.dependent_work")
    source_owners = set(string_list(work_package["source_owners"], "work_package.source_owners"))
    for owner in (
        "compat/x86_64/header_declaration_macro_visibility_matrix.toml",
        "compat/x86_64/header_declaration_macro_visibility_matrix.py",
        "compat/x86_64/generated/header_declaration_macro_visibility_matrix/report.json",
        "compat/x86_64/run_header_declaration_macro_visibility_matrix.sh",
        "compat/x86_64/tests/test_header_declaration_macro_visibility_matrix.py",
        "compat/x86_64/header_abi_matrix.toml",
        "compat/x86_64/header_abi_matrix.py",
        "compat/x86_64/generated/header_abi_matrix/report.json",
        "compat/x86_64/header_callable_visibility_matrix.toml",
        "compat/x86_64/header_callable_visibility_matrix.py",
        "compat/x86_64/header_callable_inventory.toml",
        "compat/x86_64/header_callable_inventory.py",
        "compat/x86_64/header_callable_inventory.json",
        "compat/x86_64/public_headers.txt",
        "compat/x86_64/headers-layouts-foundation.toml",
        "compat/x86_64/parity.toml",
        "compat/x86_64/validate_parity_ledger.py",
        "scripts/dev-x86_64.sh",
    ):
        require(owner in source_owners, f"declaration/macro visibility work package omits {owner}")

    raw_exceptions = raw["oracle_not_applicable"]
    require(isinstance(raw_exceptions, list), "declaration/macro visibility oracle exceptions are invalid")
    exceptions: dict[tuple[str, str], str] = {}
    for index, entry in enumerate(raw_exceptions):
        location = f"oracle_not_applicable[{index}]"
        require(
            isinstance(entry, Mapping) and set(entry) == {"header", "profile", "reason"},
            f"{location} keys changed",
        )
        header = entry["header"]
        profile = entry["profile"]
        reason = entry["reason"]
        require(isinstance(header, str) and header, f"{location}.header is invalid")
        require(isinstance(profile, str) and profile in profiles, f"{location}.profile is invalid")
        require(isinstance(reason, str) and reason, f"{location}.reason is invalid")
        key = (header, profile)
        require(key not in exceptions, f"{location} duplicates an oracle exception")
        exceptions[key] = reason
    require(
        tuple(exceptions) == (("aio.h", "c11-strict"),),
        "declaration/macro visibility oracle exception roster changed",
    )
    require(
        exceptions == dict(abi_contract.oracle_not_applicable),
        "declaration/macro visibility oracle exception source drifted",
    )
    return MatrixContract(
        source_abi_contract=source_abi_contract_path,
        source_abi_report=source_abi_report,
        callable_visibility_contract=callable_visibility_contract_path,
        public_headers=public_headers,
        generated_report=generated_report,
        profiles=profiles,
        project_only_headers=project_only_headers,
        oracle_not_applicable=exceptions,
        work_package=dict(work_package),
    )


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity_fact(value: object, location: str) -> dict[str, str]:
    require(isinstance(value, Mapping), f"{location} must be a fact")
    require(set(value) == {"kind", "name", "signature"}, f"{location} fact keys changed")
    kind = value["kind"]
    name = value["name"]
    signature = value["signature"]
    require(isinstance(kind, str) and kind in FACT_KINDS, f"{location}.kind is invalid")
    require(isinstance(name, str) and name, f"{location}.name is invalid")
    require(isinstance(signature, str) and signature, f"{location}.signature is invalid")
    return {"kind": kind, "name": name}


def canonical_identities(values: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    result = [{"kind": value["kind"], "name": value["name"]} for value in values]
    require(
        result == sorted(result, key=lambda item: (item["kind"], item["name"])),
        "source declaration facts are not ordered by identity",
    )
    require(
        len(result) == len({(item["kind"], item["name"]) for item in result}),
        "source declaration facts duplicate an identity",
    )
    return result


def derive_visibility_difference(source_difference: Mapping[str, Any]) -> dict[str, Any]:
    """Strip source spellings while retaining separately owned form differences."""

    expected_keys = {
        "candidate_only",
        "candidate_only_count",
        "incompatible",
        "incompatible_count",
        "matched_count",
        "reference_only",
        "reference_only_count",
    }
    require(set(source_difference) == expected_keys, "source declaration difference keys changed")
    candidate_raw = source_difference["candidate_only"]
    reference_raw = source_difference["reference_only"]
    incompatible_raw = source_difference["incompatible"]
    require(isinstance(candidate_raw, list), "source candidate-only facts are invalid")
    require(isinstance(reference_raw, list), "source reference-only facts are invalid")
    require(isinstance(incompatible_raw, list), "source incompatible facts are invalid")
    candidate_only = canonical_identities(
        [identity_fact(value, f"source candidate_only[{index}]") for index, value in enumerate(candidate_raw)]
    )
    reference_only = canonical_identities(
        [identity_fact(value, f"source reference_only[{index}]") for index, value in enumerate(reference_raw)]
    )
    for index, value in enumerate(incompatible_raw):
        location = f"source incompatible[{index}]"
        require(isinstance(value, Mapping), f"{location} is invalid")
        require(
            set(value) == {"candidate_signature", "kind", "name", "reference_signature"},
            f"{location} keys changed",
        )
        require(value["kind"] in FACT_KINDS and isinstance(value["name"], str) and value["name"], f"{location} identity is invalid")
        require(
            isinstance(value["candidate_signature"], str)
            and value["candidate_signature"]
            and isinstance(value["reference_signature"], str)
            and value["reference_signature"],
            f"{location} signatures are invalid",
        )
    candidate_count = source_difference["candidate_only_count"]
    reference_count = source_difference["reference_only_count"]
    incompatible_count = source_difference["incompatible_count"]
    matched_count = source_difference["matched_count"]
    require(candidate_count == len(candidate_only), "source candidate-only count drifted")
    require(reference_count == len(reference_only), "source reference-only count drifted")
    require(incompatible_count == len(incompatible_raw), "source incompatible count drifted")
    require(isinstance(matched_count, int) and matched_count >= 0, "source matched count is invalid")
    return {
        "candidate_only": candidate_only,
        "matched_count": matched_count + incompatible_count,
        "reference_only": reference_only,
        "separately_accounted_source_form_difference_count": incompatible_count,
    }


def source_summary(value: object, location: str) -> dict[str, Any]:
    """Copy an already-validated source report fact summary without widening it."""

    require(isinstance(value, Mapping), f"{location} is invalid")
    require(set(value) == {"count", "kind_counts", "sha256"}, f"{location} keys changed")
    count = value["count"]
    kind_counts = value["kind_counts"]
    digest = value["sha256"]
    require(isinstance(count, int) and count >= 0, f"{location}.count is invalid")
    require(isinstance(kind_counts, Mapping), f"{location}.kind_counts is invalid")
    require(
        all(isinstance(kind, str) and kind in FACT_KINDS and isinstance(total, int) and total > 0 for kind, total in kind_counts.items()),
        f"{location}.kind_counts is invalid",
    )
    require(sum(kind_counts.values()) == count, f"{location}.kind_counts does not sum to count")
    require(isinstance(digest, str) and len(digest) == 64, f"{location}.sha256 is invalid")
    return {"count": count, "kind_counts": dict(kind_counts), "sha256": digest}


def derive_row(source_row: Mapping[str, Any], contract: MatrixContract) -> dict[str, Any]:
    """Translate one validated source declaration-form row into identity evidence."""

    header = source_row["header"]
    profile = source_row["profile"]
    candidate = source_summary(source_row["candidate"], f"source candidate {header}:{profile}")
    candidate_status = source_row["candidate_status"]
    source_comparison = source_row["comparison"]
    require(candidate_status == "ok", f"source candidate status drifted: {header}:{profile}")
    result: dict[str, Any] = {
        "candidate": candidate,
        "candidate_status": candidate_status,
        "header": header,
        "profile": profile,
    }
    if source_comparison == "candidate-only-pending-c-abi-policy":
        require(header in contract.project_only_headers, f"source project-only path drifted: {header}")
        require(source_row["reference"] is None and source_row["reference_status"] == "not-in-pinned-inventory", f"source project-only reference drifted: {header}:{profile}")
        result.update(
            {
                "comparison": source_comparison,
                "disposition": "retained-pending-c-abi-policy",
                "reference": None,
                "reference_status": "not-in-pinned-inventory",
            }
        )
        return result
    if source_comparison == "oracle-not-applicable":
        require((header, profile) in contract.oracle_not_applicable, f"source oracle exception drifted: {header}:{profile}")
        require(source_row["reference"] is None and source_row["reference_status"] == "oracle-not-applicable", f"source oracle reference drifted: {header}:{profile}")
        result.update(
            {
                "comparison": source_comparison,
                "oracle_not_applicable_reason": contract.oracle_not_applicable[(header, profile)],
                "reference": None,
                "reference_status": "oracle-not-applicable",
            }
        )
        return result

    require(source_comparison in {"matched", "mismatch"}, f"source comparison drifted: {header}:{profile}")
    reference = source_summary(source_row["reference"], f"source reference {header}:{profile}")
    require(source_row["reference_status"] == "ok", f"source reference status drifted: {header}:{profile}")
    if source_comparison == "matched":
        require(candidate["count"] == reference["count"], f"source matched dimensions drifted: {header}:{profile}")
        difference = {
            "candidate_only": [],
            "matched_count": candidate["count"],
            "reference_only": [],
            "separately_accounted_source_form_difference_count": 0,
        }
    else:
        source_difference = source_row["difference"]
        require(isinstance(source_difference, Mapping), f"source difference is invalid: {header}:{profile}")
        difference = derive_visibility_difference(source_difference)
        require(
            candidate["count"] == difference["matched_count"] + len(difference["candidate_only"])
            and reference["count"] == difference["matched_count"] + len(difference["reference_only"]),
            f"derived visibility dimensions drifted: {header}:{profile}",
        )
    comparison = (
        "matched"
        if not difference["candidate_only"] and not difference["reference_only"]
        else "mismatch"
    )
    result.update(
        {
            "candidate_only": difference["candidate_only"],
            "comparison": comparison,
            "matched_identity_count": difference["matched_count"],
            "reference": reference,
            "reference_only": difference["reference_only"],
            "reference_status": "ok",
            "separately_accounted_source_form_difference_count": difference[
                "separately_accounted_source_form_difference_count"
            ],
            "source_form_comparison": source_comparison,
        }
    )
    return result


def load_source_report(contract: MatrixContract) -> Mapping[str, Any]:
    """Read only a valid checked source report; the runner refreshes it natively."""

    try:
        source = json.loads(contract.source_abi_report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HeaderDeclarationMacroVisibilityMatrixError(
            f"cannot read source declaration-form report: {error}"
        ) from error
    require(isinstance(source, Mapping), "source declaration-form report must be a table")
    try:
        header_abi_matrix.validate_checked_report(source, header_abi_matrix.load_contract())
    except header_abi_matrix.HeaderAbiMatrixError as error:
        raise HeaderDeclarationMacroVisibilityMatrixError(
            f"source declaration-form report is invalid: {error}"
        ) from error
    return source


def build_report(contract: MatrixContract | None = None) -> dict[str, Any]:
    """Derive the checked identity matrix without repeating compiler collection."""

    contract = load_contract() if contract is None else contract
    source = load_source_report(contract)
    source_rows = source["rows"]
    require(isinstance(source_rows, list), "source declaration-form rows are invalid")
    rows = [derive_row(row, contract) for row in source_rows]
    comparison_counts: Counter[str] = Counter(row["comparison"] for row in rows)
    source_form_counts: Counter[str] = Counter(source_row["comparison"] for source_row in source_rows)
    candidate_only_kind_counts: Counter[str] = Counter()
    reference_only_kind_counts: Counter[str] = Counter()
    candidate_only_identity_count = 0
    reference_only_identity_count = 0
    matched_identity_count = 0
    project_only_candidate_fact_count = 0
    oracle_not_applicable_candidate_fact_count = 0
    source_form_difference_count = 0
    source_form_difference_row_count = 0
    source_form_only_difference_row_count = 0
    for row in rows:
        comparison = row["comparison"]
        if comparison == "candidate-only-pending-c-abi-policy":
            project_only_candidate_fact_count += int(row["candidate"]["count"])
            continue
        if comparison == "oracle-not-applicable":
            oracle_not_applicable_candidate_fact_count += int(row["candidate"]["count"])
            continue
        candidate_only = row["candidate_only"]
        reference_only = row["reference_only"]
        matched_identity_count += int(row["matched_identity_count"])
        candidate_only_identity_count += len(candidate_only)
        reference_only_identity_count += len(reference_only)
        candidate_only_kind_counts.update(item["kind"] for item in candidate_only)
        reference_only_kind_counts.update(item["kind"] for item in reference_only)
        source_form_difference = int(row["separately_accounted_source_form_difference_count"])
        source_form_difference_count += source_form_difference
        if source_form_difference:
            source_form_difference_row_count += 1
            if comparison == "matched":
                source_form_only_difference_row_count += 1

    mismatch_rows = comparison_counts["mismatch"]
    oracle_rows = comparison_counts["oracle-not-applicable"]
    project_rows = comparison_counts["candidate-only-pending-c-abi-policy"]
    summary = {
        "candidate_only_identity_count": candidate_only_identity_count,
        "candidate_only_identity_kind_counts": dict(sorted(candidate_only_kind_counts.items())),
        "candidate_public_header_count": 191,
        "comparable_row_count": comparison_counts["matched"] + mismatch_rows,
        "comparison_counts": dict(sorted(comparison_counts.items())),
        "complete": False,
        "incomplete_reasons": [
            f"{mismatch_rows} comparable pinned header/profile rows have declaration or macro identity visibility differences",
            f"{oracle_rows} pinned-musl header/profile rows are oracle-not-applicable",
            f"{project_rows} project-only header/profile rows remain pending C ABI policy",
            "declaration-form equality, record byte layouts, archive linkage, runtime behavior, family promotion, and public support remain outside this partial matrix",
        ],
        "matched_identity_count": matched_identity_count,
        "mismatch_row_count": mismatch_rows,
        "oracle_not_applicable_candidate_fact_count": oracle_not_applicable_candidate_fact_count,
        "oracle_not_applicable_row_count": oracle_rows,
        "pinned_public_header_count": 183,
        "pinned_row_count": 183 * len(contract.profiles),
        "profile_count": len(contract.profiles),
        "project_only_candidate_fact_count": project_only_candidate_fact_count,
        "project_only_header_count": len(contract.project_only_headers),
        "project_only_row_count": project_rows,
        "reference_only_identity_count": reference_only_identity_count,
        "reference_only_identity_kind_counts": dict(sorted(reference_only_kind_counts.items())),
        "row_count": len(rows),
        "source_form_comparison_counts": dict(sorted(source_form_counts.items())),
        "source_form_difference_count": source_form_difference_count,
        "source_form_difference_row_count": source_form_difference_row_count,
        "source_form_only_difference_row_count": source_form_only_difference_row_count,
    }
    return {
        "schema": SCHEMA,
        "contract_schema": CONTRACT_SCHEMA,
        "target": TARGET,
        "platform": PLATFORM,
        "oracle": ORACLE,
        "inputs": {
            "callable_visibility_contract_sha256": sha256_file(contract.callable_visibility_contract),
            "declaration_macro_visibility_matrix_contract_sha256": sha256_file(CONTRACT_PATH),
            "public_header_inventory_sha256": sha256_file(contract.public_headers),
            "source_abi_contract_sha256": sha256_file(contract.source_abi_contract),
            "source_abi_report_sha256": sha256_file(contract.source_abi_report),
        },
        "scope": dict(POLICY),
        "work_package": dict(contract.work_package),
        "profiles": source["profiles"],
        "project_only_headers": [
            {"disposition": "retained-pending-c-abi-policy", "path": header}
            for header in contract.project_only_headers
        ],
        "rows": rows,
        "summary": summary,
    }


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def validate_checked_report(report: Mapping[str, Any], contract: MatrixContract) -> None:
    """Reject an altered or stale derived report without repeating compilation."""

    require(isinstance(report, Mapping), "checked declaration/macro visibility report must be a table")
    require(
        report == build_report(contract),
        "checked declaration/macro visibility report is stale or malformed; regenerate with --write",
    )


def check_output(path: Path, rendered: str) -> None:
    try:
        existing = path.read_text(encoding="utf-8")
    except OSError as error:
        raise HeaderDeclarationMacroVisibilityMatrixError(
            f"checked declaration/macro visibility report is missing: {path.relative_to(ROOT)} ({error})"
        ) from error
    require(
        existing == rendered,
        f"checked declaration/macro visibility report is stale: regenerate {path.relative_to(ROOT)} with --write",
    )


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="update the reviewed checked report")
    parser.add_argument("--check", action="store_true", help="require the checked report to match the source ABI report")
    parsed = parser.parse_args(arguments)
    require(not (parsed.write and parsed.check), "--write and --check cannot be combined")
    contract = load_contract()
    report = build_report(contract)
    rendered = canonical_json(report)
    if parsed.write:
        require(not contract.generated_report.is_symlink(), "checked declaration/macro visibility report path is a symlink")
        contract.generated_report.parent.mkdir(parents=True, exist_ok=True)
        contract.generated_report.write_text(rendered, encoding="utf-8")
    elif parsed.check:
        check_output(contract.generated_report, rendered)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HeaderDeclarationMacroVisibilityMatrixError as error:
        print(f"ERROR: x86 header declaration/macro visibility matrix: {error}", file=sys.stderr)
        raise SystemExit(1)
