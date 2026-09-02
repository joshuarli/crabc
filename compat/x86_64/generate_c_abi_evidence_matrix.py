#!/usr/bin/env python3
"""Validate and materialize routine native x86 C ABI evidence rows.

The matrix is intentionally narrow.  It is a reusable source of generated
prototype/function-pointer probes, direct-call static entry harnesses, and
focused runner wiring for ordinary C ABI leaves.  Rows with a contract that
does not fit a template must say why rather than silently acquiring bespoke
boilerplate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "compat" / "x86_64" / "c_abi_evidence_matrix.toml"
PARITY_PATH = ROOT / "compat" / "x86_64" / "parity.toml"
CAPABILITY_PATH = ROOT / "compat" / "crabc-rs" / "coverage.toml"
STATIC_EXPORTS_PATH = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
GENERATED_DIRECTORY = Path("compat/x86_64/generated/c_abi_evidence_matrix")
SCHEMA = "crabc.x86_64-c-abi-evidence-matrix/v1"
REPORT_SCHEMA = "crabc.x86_64-c-abi-evidence-matrix-report/v1"
TARGET = "x86_64-unknown-linux-musl"
PLATFORM = "Linux/x86-64 little-endian"
TEMPLATE_ID = "noarg-scalar-static-v1"
FAMILY_AGGREGATE_COMMAND = "./scripts/dev-x86_64.sh routine-c-abi-matrix"
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]*$")
SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
BESPOKE_CLASSES = {
    "unusual-feature-visibility-or-cxx-linkage",
    "variadic-calling-convention",
    "callback-or-ownership-transition",
    "opaque-object-identity-or-lifetime",
    "target-specific-public-layout",
    "fenv-or-long-double-state",
    "tls-tcb-cancellation-fork-or-signal",
    "process-entry-or-nonstandard-syscall-abi",
    "elf-mapping-lifecycle-privilege-namespace-or-network",
    "semantic-negative-scope-exception",
}


class MatrixError(ValueError):
    """The routine C ABI matrix is not a complete, unambiguous contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MatrixError(message)


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise MatrixError(f"cannot load {path.relative_to(ROOT)}: {error}") from error
    require(isinstance(document, dict), f"{path.relative_to(ROOT)} must contain a TOML table")
    return document


def checked_string(value: object, location: str) -> str:
    require(isinstance(value, str) and value, f"{location} must be a nonempty string")
    return value


def checked_string_list(value: object, location: str, *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{location} must be a list")
    result = [checked_string(item, f"{location}[{index}]") for index, item in enumerate(value)]
    require(allow_empty or bool(result), f"{location} must not be empty")
    require(len(result) == len(set(result)), f"{location} has duplicate values")
    return result


def project_path(value: object, location: str) -> str:
    path = checked_string(value, location)
    candidate = Path(path)
    require(not candidate.is_absolute() and ".." not in candidate.parts, f"{location} escapes the repository")
    require((ROOT / candidate).is_file(), f"{location} does not name a tracked file: {path}")
    return path


def parity_ownership() -> tuple[dict[str, str], set[str]]:
    parity = load_toml(PARITY_PATH)
    promotion = parity.get("promotion")
    families = parity.get("family")
    require(isinstance(promotion, Mapping) and isinstance(families, list), "parity ledger family roster is invalid")
    required = checked_string_list(promotion.get("required_families"), "parity.promotion.required_families")
    owners: dict[str, str] = {}
    for index, family in enumerate(families):
        require(isinstance(family, Mapping), f"parity.family[{index}] is invalid")
        identifier = checked_string(family.get("id"), f"parity.family[{index}].id")
        capabilities = checked_string_list(
            family.get("capabilities"),
            f"parity.family[{index}].capabilities",
            allow_empty=True,
        )
        for capability in capabilities:
            require(capability not in owners, f"parity capability {capability} has multiple families")
            owners[capability] = identifier
    require(set(required) == {checked_string(item.get("id"), "parity.family.id") for item in families if isinstance(item, Mapping)}, "parity required-family roster drifted")
    return owners, set(required)


def baseline_capabilities() -> set[str]:
    baseline = load_toml(CAPABILITY_PATH)
    entries = baseline.get("capability")
    require(isinstance(entries, list), "AArch64 capability ledger has no capability list")
    result: set[str] = set()
    for index, entry in enumerate(entries):
        require(isinstance(entry, Mapping), f"AArch64 capability[{index}] is invalid")
        identifier = checked_string(entry.get("id"), f"AArch64 capability[{index}].id")
        require(identifier not in result, f"AArch64 capability {identifier} is duplicated")
        result.add(identifier)
    return result


def static_exports() -> set[str]:
    try:
        lines = STATIC_EXPORTS_PATH.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise MatrixError(f"cannot read {STATIC_EXPORTS_PATH.relative_to(ROOT)}: {error}") from error
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


def normalized_identifier(identifier: str) -> str:
    return identifier.replace("-", "_")


def named_function_pointer(pointer_type: str, name: str) -> str:
    """Insert a declarator name into the matrix's C function-pointer spelling."""
    require(pointer_type.count("(*)") == 1, f"function-pointer type cannot name {name}: {pointer_type!r}")
    return pointer_type.replace("(*)", f"(*{name})")


def validate_matrix(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    require(document.get("schema") == SCHEMA, "matrix schema changed")
    require(document.get("target") == TARGET, "matrix target changed")
    require(document.get("platform") == PLATFORM, "matrix platform changed")
    policy = document.get("policy")
    require(isinstance(policy, Mapping), "matrix policy is missing")
    require(policy.get("native_execution_only") is True, "matrix must require native execution")
    require(policy.get("public_support") is False, "matrix cannot claim public support")
    require(policy.get("historical_retrofit_required") is False, "matrix cannot require historical retrofit")

    templates = document.get("template")
    require(isinstance(templates, Mapping), "matrix templates are missing")
    routine_template = templates.get(TEMPLATE_ID)
    require(isinstance(routine_template, Mapping), f"matrix template {TEMPLATE_ID} is missing")
    require(
        routine_template == {
            "c_probe": "prototype-function-pointer",
            "cxx_probe": "prototype-function-pointer-c-linkage",
            "static_entry": "direct-call-exit",
            "oracle_candidate": "existing-focused-runner",
            "export_check": "static-c-abi-export-ratchet",
        },
        "routine matrix template drifted",
    )

    owners, required_families = parity_ownership()
    capabilities = baseline_capabilities()
    exports = static_exports()
    family_entries = document.get("family")
    require(isinstance(family_entries, list) and family_entries, "matrix families are missing")
    aggregates: dict[str, str] = {}
    for index, family in enumerate(family_entries):
        require(isinstance(family, Mapping), f"matrix.family[{index}] is invalid")
        identifier = checked_string(family.get("id"), f"matrix.family[{index}].id")
        require(identifier in required_families, f"matrix family {identifier} is not a required parity family")
        require(identifier not in aggregates, f"matrix family {identifier} is duplicated")
        command = checked_string(family.get("aggregate_command"), f"matrix.family[{index}].aggregate_command")
        require(
            command == f"{FAMILY_AGGREGATE_COMMAND} {identifier}",
            f"matrix family {identifier} has the wrong aggregate command",
        )
        aggregates[identifier] = command

    rows = document.get("row")
    require(isinstance(rows, list) and rows, "matrix rows are missing")
    normalized_rows: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for index, original in enumerate(rows):
        location = f"matrix.row[{index}]"
        require(isinstance(original, Mapping), f"{location} is invalid")
        row = dict(original)
        identifier = checked_string(row.get("id"), f"{location}.id")
        require(IDENTIFIER.fullmatch(identifier) is not None, f"{location}.id is not a stable identifier")
        require(identifier not in identifiers, f"matrix row {identifier} is duplicated")
        identifiers.add(identifier)
        symbols = checked_string_list(row.get("symbols"), f"{location}.symbols")
        data_objects = checked_string_list(row.get("data_objects"), f"{location}.data_objects", allow_empty=True)
        require(all(SYMBOL.fullmatch(item) for item in [*symbols, *data_objects]), f"{location} has an invalid C symbol or data-object name")
        capability = checked_string(row.get("owner_capability"), f"{location}.owner_capability")
        family = checked_string(row.get("owner_family"), f"{location}.owner_family")
        require(capability in capabilities, f"{location}.owner_capability is not frozen")
        require(owners.get(capability) == family, f"{location}.owner_family does not own {capability}")
        require(family in aggregates, f"{location}.owner_family has no matrix aggregate")
        checked_string(row.get("completion_obligation"), f"{location}.completion_obligation")
        profiles = checked_string_list(row.get("header_profiles"), f"{location}.header_profiles")
        require(any(profile.startswith("c11-") for profile in profiles), f"{location} has no C header profile")
        require(any(profile.startswith("cxx17-") for profile in profiles), f"{location} has no C++ header profile")
        checked_string_list(row.get("headers"), f"{location}.headers")
        checked_string(row.get("c_signature_class"), f"{location}.c_signature_class")
        checked_string(row.get("cxx_signature_class"), f"{location}.cxx_signature_class")
        c_pointer_type = checked_string(row.get("c_pointer_type"), f"{location}.c_pointer_type")
        cxx_pointer_type = checked_string(row.get("cxx_pointer_type"), f"{location}.cxx_pointer_type")
        require(row.get("binding") == "strong", f"{location}.binding must name the ordinary strong binding")
        require(row.get("visibility") == "default", f"{location}.visibility must name the ordinary default visibility")
        aliases = checked_string_list(row.get("aliases"), f"{location}.aliases", allow_empty=True)
        expected_exports = checked_string_list(row.get("expected_exports"), f"{location}.expected_exports")
        require(set(expected_exports) == set(symbols) | set(aliases), f"{location}.expected_exports must equal symbols plus aliases")
        require(set(expected_exports) <= exports, f"{location}.expected_exports are absent from the static export ratchet")
        template = row.get("template")
        bespoke_reason = row.get("bespoke_reason")
        if template is None:
            checked_string(bespoke_reason, f"{location}.bespoke_reason")
            bespoke_class = checked_string(row.get("bespoke_class"), f"{location}.bespoke_class")
            require(bespoke_class in BESPOKE_CLASSES, f"{location}.bespoke_class is not an admitted template exception")
            routine_eligible = (
                len(symbols) == 1
                and not data_objects
                and "(void)" in c_pointer_type
                and "(void)" in cxx_pointer_type
                and "non-variadic" in str(row["c_signature_class"])
            )
            require(not routine_eligible, f"{location} fits {TEMPLATE_ID}; a bespoke_reason cannot bypass the routine template")
        else:
            require(template == TEMPLATE_ID, f"{location}.template is unknown")
            require(bespoke_reason is None, f"{location}.bespoke_reason is allowed only for non-template rows")
            require(len(symbols) == 1 and not data_objects, f"{location} does not fit the no-argument scalar template")
            require("(void)" in c_pointer_type and "(void)" in cxx_pointer_type, f"{location} does not describe a no-argument function")
        checked_string(row.get("oracle_route"), f"{location}.oracle_route")
        checked_string(row.get("expected_behavior_class"), f"{location}.expected_behavior_class")
        header_runner = project_path(row.get("header_runner"), f"{location}.header_runner")
        focused_runner = project_path(row.get("focused_runner"), f"{location}.focused_runner")
        focused_command = checked_string(row.get("focused_command"), f"{location}.focused_command")
        require(focused_command.startswith("./scripts/dev-x86_64.sh "), f"{location}.focused_command is not a canonical x86 dispatcher command")
        family_aggregate = checked_string(row.get("family_aggregate"), f"{location}.family_aggregate")
        require(family_aggregate == family, f"{location}.family_aggregate must equal owner_family")
        normalized_rows.append(
            {
                "id": identifier,
                "symbols": symbols,
                "data_objects": data_objects,
                "owner_capability": capability,
                "owner_family": family,
                "completion_obligation": row["completion_obligation"],
                "header_profiles": profiles,
                "headers": checked_string_list(row["headers"], f"{location}.headers"),
                "c_signature_class": row["c_signature_class"],
                "cxx_signature_class": row["cxx_signature_class"],
                "c_pointer_type": c_pointer_type,
                "cxx_pointer_type": cxx_pointer_type,
                "binding": "strong",
                "visibility": "default",
                "aliases": aliases,
                "expected_exports": expected_exports,
                "template": template,
                "bespoke_reason": bespoke_reason,
                "bespoke_class": row.get("bespoke_class"),
                "oracle_route": row["oracle_route"],
                "expected_behavior_class": row["expected_behavior_class"],
                "header_runner": header_runner,
                "focused_runner": focused_runner,
                "focused_command": focused_command,
                "family_aggregate": family_aggregate,
            }
        )
    for family in aggregates:
        require(
            any(row["owner_family"] == family for row in normalized_rows),
            f"matrix family {family} has no routine rows",
        )
    return normalized_rows


def c_probe(row: Mapping[str, Any]) -> str:
    identifier = normalized_identifier(str(row["id"]))
    symbol = row["symbols"][0]
    header = row["headers"][0]
    signature = f"crabc_{identifier}_signature"
    function = f"crabc_{identifier}_function"
    return f"""/* Generated from c_abi_evidence_matrix.toml; do not edit. */
#include <{header}>

typedef {named_function_pointer(str(row['c_pointer_type']), signature)};
_Static_assert(__builtin_types_compatible_p(__typeof__(&{symbol}),
    {signature}), "{symbol} C declaration");
static {named_function_pointer(str(row['c_pointer_type']), function)} = {symbol};

int crabc_{identifier}_prototype_probe(void)
{{
    return {function} != ({signature})0 ? 0 : 1;
}}
"""


def cxx_probe(row: Mapping[str, Any]) -> str:
    identifier = normalized_identifier(str(row["id"]))
    symbol = row["symbols"][0]
    header = row["headers"][0]
    return f"""/* Generated from c_abi_evidence_matrix.toml; do not edit. */
#include <{header}>

using crabc_{identifier}_signature = {row['cxx_pointer_type']};
static_assert(__is_same(decltype(&{symbol}), crabc_{identifier}_signature),
    "{symbol} C++ declaration");
static crabc_{identifier}_signature crabc_{identifier}_function = {symbol};

int crabc_{identifier}_prototype_probe_cpp()
{{
    return crabc_{identifier}_function != nullptr ? 0 : 1;
}}
"""


def static_entry(row: Mapping[str, Any]) -> str:
    symbol = row["symbols"][0]
    return f"""# Generated from c_abi_evidence_matrix.toml; do not edit.
.text
.globl _start
.type _start,@function
_start:
    call {symbol}
    xor %edi, %edi
    mov $60, %eax
    syscall
.size _start, .-_start
"""


def runner(row: Mapping[str, Any]) -> str:
    return f"""#!/usr/bin/env bash
# Generated from c_abi_evidence_matrix.toml; do not edit.
# The focused runner owns the pinned-musl oracle/candidate build-and-run and
# static export check; the checked matrix family aggregate executes this wrapper.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")/../../../../.." && pwd)"
bash "$ROOT_DIR/{row['header_runner']}"
bash "$ROOT_DIR/{row['focused_runner']}"
"""


def output_relpaths(rows: list[dict[str, Any]]) -> list[Path]:
    paths = [GENERATED_DIRECTORY / "report.json"]
    for row in rows:
        prefix = GENERATED_DIRECTORY / row["id"]
        paths.append(prefix / "run.sh")
        if row["template"] is not None:
            paths.extend((prefix / "header_probe.c", prefix / "header_probe.cpp", prefix / "start.S"))
    return paths


def generated_row_outputs(row: Mapping[str, Any]) -> dict[str, str]:
    """Describe the checked paths that one matrix row can execute."""
    prefix = GENERATED_DIRECTORY / str(row["id"])
    outputs = {"routine_runner": str(prefix / "run.sh")}
    if row["template"] is not None:
        outputs = {
            "c_probe": str(prefix / "header_probe.c"),
            "cxx_probe": str(prefix / "header_probe.cpp"),
            "static_entry": str(prefix / "start.S"),
            **outputs,
        }
    return outputs


def generated_report(document: Mapping[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    families = document["family"]
    assert isinstance(families, list)
    return {
        "schema": REPORT_SCHEMA,
        "matrix_schema": SCHEMA,
        "matrix_sha256": hashlib.sha256(MATRIX_PATH.read_bytes()).hexdigest(),
        "target": TARGET,
        "platform": PLATFORM,
        "families": [
            {
                "id": family["id"],
                "aggregate_command": family["aggregate_command"],
                "row_ids": [row["id"] for row in rows if row["owner_family"] == family["id"]],
            }
            for family in families
        ],
        "rows": [
            {
                "id": row["id"],
                "symbols": row["symbols"],
                "data_objects": row["data_objects"],
                "owner": {"capability": row["owner_capability"], "family": row["owner_family"]},
                "completion_obligation": row["completion_obligation"],
                "header": {"profiles": row["header_profiles"], "headers": row["headers"], "c_signature_class": row["c_signature_class"], "cxx_signature_class": row["cxx_signature_class"]},
                "linkage": {"binding": row["binding"], "visibility": row["visibility"], "aliases": row["aliases"], "expected_exports": row["expected_exports"]},
                "ledger_fields": {
                    "owner_capability": row["owner_capability"],
                    "owner_family": row["owner_family"],
                    "completion_obligation": row["completion_obligation"],
                    "expected_exports": row["expected_exports"],
                    "focused_command": row["focused_command"],
                    "family_aggregate": row["family_aggregate"],
                },
                "template": row["template"],
                "bespoke_reason": row["bespoke_reason"],
                "bespoke_class": row["bespoke_class"],
                "oracle": {"route": row["oracle_route"], "behavior_class": row["expected_behavior_class"]},
                "generated": generated_row_outputs(row),
                "execution": {"header_probe": row["header_runner"], "oracle_candidate_build_run_and_export_check": row["focused_runner"], "focused_command": row["focused_command"], "family_aggregate": row["family_aggregate"]},
            }
            for row in rows
        ],
    }


def build_outputs(document: Mapping[str, Any]) -> dict[Path, str]:
    rows = validate_matrix(document)
    outputs: dict[Path, str] = {}
    report = generated_report(document, rows)
    outputs[GENERATED_DIRECTORY / "report.json"] = json.dumps(report, indent=2, sort_keys=True) + "\n"
    for row in rows:
        prefix = GENERATED_DIRECTORY / row["id"]
        if row["template"] == TEMPLATE_ID:
            outputs[prefix / "header_probe.c"] = c_probe(row)
            outputs[prefix / "header_probe.cpp"] = cxx_probe(row)
            outputs[prefix / "start.S"] = static_entry(row)
        outputs[prefix / "run.sh"] = runner(row)
    require(set(outputs) == set(output_relpaths(rows)), "template output set is incomplete")
    return outputs


def write_outputs(outputs: Mapping[Path, str], output_root: Path) -> None:
    for relative, content in outputs.items():
        path = output_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        if path.name == "run.sh":
            path.chmod(0o755)


def check_outputs(outputs: Mapping[Path, str], output_root: Path) -> None:
    expected = set(outputs)
    observed_root = output_root / GENERATED_DIRECTORY
    observed = {path.relative_to(output_root) for path in observed_root.rglob("*") if path.is_file()} if observed_root.exists() else set()
    require(observed == expected, "generated routine matrix output set drifted")
    for relative, content in outputs.items():
        path = output_root / relative
        try:
            actual = path.read_text(encoding="utf-8")
        except OSError as error:
            raise MatrixError(f"missing generated output {relative}: {error}") from error
        require(actual == content, f"generated routine matrix output drifted: {relative}")
        if path.name == "run.sh":
            require(path.stat().st_mode & 0o111, f"generated routine runner is not executable: {relative}")


def checked_generated_report(
    outputs: Mapping[Path, str],
    output_root: Path,
) -> dict[str, Any]:
    """Load the checked registry after proving it exactly matches matrix source."""
    report_relative = GENERATED_DIRECTORY / "report.json"
    expected = outputs.get(report_relative)
    require(expected is not None, "generated routine matrix report is missing from output set")
    report_path = output_root / report_relative
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MatrixError(f"cannot load checked generated routine matrix report: {error}") from error
    require(isinstance(report, dict), "checked generated routine matrix report is not an object")
    require(report.get("schema") == REPORT_SCHEMA, "checked generated routine matrix report schema drifted")
    require(
        report == json.loads(expected),
        "checked generated routine matrix report does not match matrix source",
    )
    require(
        report.get("matrix_sha256") == hashlib.sha256(MATRIX_PATH.read_bytes()).hexdigest(),
        "checked generated routine matrix report matrix digest drifted",
    )
    return report


def generated_runner_path(
    row_identifier: str,
    row: Mapping[str, Any],
    output_root: Path,
) -> Path:
    generated = row.get("generated")
    require(isinstance(generated, Mapping), f"matrix row {row_identifier} has no generated registry")
    runner_text = checked_string(
        generated.get("routine_runner"),
        f"matrix row {row_identifier}.generated.routine_runner",
    )
    relative = Path(runner_text)
    require(
        not relative.is_absolute() and ".." not in relative.parts,
        f"matrix row {row_identifier}.generated.routine_runner escapes generated output",
    )
    expected = GENERATED_DIRECTORY / row_identifier / "run.sh"
    require(
        relative == expected,
        f"matrix row {row_identifier}.generated.routine_runner is not its deterministic runner",
    )
    generated_root = (output_root / GENERATED_DIRECTORY).resolve()
    path = output_root / relative
    require(not path.is_symlink(), f"matrix row {row_identifier} generated runner must not be a symlink")
    resolved = path.resolve()
    try:
        resolved.relative_to(generated_root)
    except ValueError as error:
        raise MatrixError(
            f"matrix row {row_identifier}.generated.routine_runner escapes generated output"
        ) from error
    require(resolved.is_file(), f"matrix row {row_identifier} generated runner is not a regular file")
    require(
        resolved.stat().st_mode & 0o111,
        f"matrix row {row_identifier} generated runner is not executable",
    )
    return resolved


def run_family(
    document: Mapping[str, Any],
    output_root: Path,
    family_identifier: str,
    *,
    outputs: Mapping[Path, str] | None = None,
) -> int:
    """Execute one validated family in checked generated-row order."""
    if outputs is None:
        outputs = build_outputs(document)
    check_outputs(outputs, output_root)
    report = checked_generated_report(outputs, output_root)
    family_identifier = checked_string(family_identifier, "matrix family identifier")
    families = report.get("families")
    rows = report.get("rows")
    require(isinstance(families, list), "checked generated routine matrix report has no families")
    require(isinstance(rows, list), "checked generated routine matrix report has no rows")

    matches = [entry for entry in families if isinstance(entry, Mapping) and entry.get("id") == family_identifier]
    require(len(matches) == 1, f"unknown matrix family: {family_identifier}")
    family = matches[0]
    row_identifiers = checked_string_list(
        family.get("row_ids"),
        f"matrix family {family_identifier}.row_ids",
    )
    expected_command = f"{FAMILY_AGGREGATE_COMMAND} {family_identifier}"
    require(
        family.get("aggregate_command") == expected_command,
        f"matrix family {family_identifier} aggregate command drifted",
    )

    rows_by_id: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        require(isinstance(row, Mapping), f"matrix report row[{index}] is invalid")
        identifier = checked_string(row.get("id"), f"matrix report row[{index}].id")
        require(identifier not in rows_by_id, f"matrix report row {identifier} is duplicated")
        rows_by_id[identifier] = row

    for identifier in row_identifiers:
        row = rows_by_id.get(identifier)
        require(row is not None, f"matrix family {family_identifier} names unknown row {identifier}")
        owner = row.get("owner")
        require(isinstance(owner, Mapping), f"matrix report row {identifier} has no owner")
        require(
            owner.get("family") == family_identifier,
            f"matrix family {family_identifier} does not own row {identifier}",
        )
        path = generated_runner_path(identifier, row, output_root)
        completed = subprocess.run([str(path)], cwd=ROOT, check=False)
        if completed.returncode != 0:
            return completed.returncode
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--write", action="store_true", help="materialize reviewed generated outputs")
    action.add_argument(
        "--run-family",
        metavar="FAMILY-ID",
        help="run one family through its checked generated routine registry",
    )
    parser.add_argument("--check", action="store_true", help="check checked-in generated outputs (default)")
    arguments = parser.parse_args()
    document = load_toml(MATRIX_PATH)
    outputs = build_outputs(document)
    if arguments.write:
        write_outputs(outputs, ROOT)
    check_outputs(outputs, ROOT)
    if arguments.run_family is not None:
        result = run_family(document, ROOT, arguments.run_family, outputs=outputs)
        if result != 0:
            return result
    print(f"x86 routine C ABI evidence matrix: PASS ({len(outputs) - 1} generated routine artifacts; {len(document['row'])} rows)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MatrixError as error:
        raise SystemExit(f"x86 routine C ABI evidence matrix: ERROR: {error}") from error
