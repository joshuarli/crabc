#!/usr/bin/env python3
"""Emit the current x86-64 parity campaign state as canonical JSON.

The report is a view over the validated frozen AArch64 baseline and current
``parity.toml``.  It is intentionally not a checked-in status snapshot: a
family, capability, or gate changes only when its source contract changes.

The dispatcher-facing interface is deliberately small:

* ``python3 compat/x86_64/campaign_report.py`` writes the whole report to
  stdout.
* ``--family ID`` writes one required-family view while retaining the frozen
  identity and report schema needed to interpret it.
* ``--output PATH`` writes the same canonical JSON to a file instead.

This script performs no evidence execution.  It validates the frozen baseline
and ledger accounting before it reports their current declared state; the
commands in the result name the native evidence which must prove a transition.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import aarch64_parity_inventory as inventory
import dynamic_product_contract as dynamic_product
import generate_c_abi_evidence_matrix as c_abi_matrix
import generate_qualification_manifest as qualification_manifest
import validate_parity_ledger as ledger
import validate_loader_libc_tls_runtime_v1 as tls_runtime_v1


ROOT = Path(__file__).resolve().parents[2]
LEDGER_PATH = ROOT / "compat" / "x86_64" / "parity.toml"
STATIC_PRODUCT_CONTRACT_PATH = ROOT / "compat" / "x86_64" / "static-product.toml"
SCHEMA = "crabc.x86_64-campaign-report/v1"
COMPLETED_STATUS = "foundation-verified"

# Product gates are not yet represented as independent ledger families.  These
# anchors keep the report honest: the gate remains unconfigured until later
# phases add a machine-checked product command, while its prerequisite state is
# still visible from the closed family graph.
DYNAMIC_PRODUCT_GATE_ANCHOR = "sysroot.owned-artifact"
QUALIFICATION_CHAIN = (
    "compat.abi-differential",
    "compat.posix-process",
    "compat.resolver-network",
    "compat.loader-corpus",
    "consumer.rust-std-lto",
    "consumer.source-build",
    "capability.accounting",
    "performance.release",
)
MATRIX_CHECK_COMMAND = (
    "python3 compat/x86_64/generate_c_abi_evidence_matrix.py --check"
)
QUALIFICATION_MANIFEST_CHECK_COMMAND = (
    "python3 compat/x86_64/generate_qualification_manifest.py --check"
)
QUALIFICATION_RUNNER_COMMAND = "./scripts/dev-x86_64.sh qualification-manifest"
STATIC_PRODUCT_RUNNER_COMMAND = "./scripts/dev-x86_64.sh owned-static-sysroot"
DYNAMIC_PRODUCT_RUNNER_COMMAND = "./scripts/dev-x86_64.sh owned-dynamic-sysroot"
TLS_RUNTIME_V1_CHECK_COMMAND = (
    "python3 compat/x86_64/validate_loader_libc_tls_runtime_v1.py --json"
)
DYNAMIC_PRODUCT_CONTRACT_CHECK_COMMAND = (
    "python3 compat/x86_64/dynamic_product_contract.py --check"
)


class CampaignReportError(ValueError):
    """The current campaign contract cannot be converted into a report."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CampaignReportError(message)


def load_validated_campaign_inputs() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    """Normalize independent validator failures at the campaign boundary."""
    try:
        frozen_baseline = inventory.validate_frozen_baseline()
        data = load_ledger()
        ledger.validate_ledger(data)
        inventory_report = inventory.build_inventory()
        static_product_contract = load_static_product_contract()
        dynamic_product_report = validate_dynamic_product_contract()
        matrix_report = validate_routine_c_abi_matrix()
        qualification_manifest_report = validate_qualification_manifest()
        tls_runtime_v1_report = validate_tls_runtime_v1_contract()
    except (
        inventory.InventoryError,
        ledger.LedgerError,
        dynamic_product.ProductContractError,
        c_abi_matrix.MatrixError,
        qualification_manifest.QualificationManifestError,
        tls_runtime_v1.TlsRuntimeContractError,
    ) as error:
        raise CampaignReportError(f"campaign input validation failed: {error}") from error
    return (
        frozen_baseline,
        data,
        inventory_report,
        static_product_contract,
        dynamic_product_report,
        matrix_report,
        qualification_manifest_report,
        tls_runtime_v1_report,
    )


def load_ledger() -> dict[str, Any]:
    try:
        with LEDGER_PATH.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CampaignReportError(f"cannot load {LEDGER_PATH.relative_to(ROOT)}: {error}") from error
    require(isinstance(value, dict), "x86 parity ledger must be a TOML table")
    return value


def load_static_product_contract() -> dict[str, Any]:
    """Load the independently validated static-product gate declaration."""
    try:
        with STATIC_PRODUCT_CONTRACT_PATH.open("rb") as stream:
            value = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CampaignReportError(
            f"cannot load {STATIC_PRODUCT_CONTRACT_PATH.relative_to(ROOT)}: {error}"
        ) from error
    require(isinstance(value, dict), "static product contract must be a TOML table")
    require(
        value.get("schema") == "crabc.x86_64-owned-static-product/v1",
        "static product contract schema is invalid",
    )
    require(
        isinstance(value.get("owner_family"), str) and value["owner_family"],
        "static product contract owner_family is invalid",
    )
    require(
        isinstance(value.get("status"), str) and value["status"],
        "static product contract status is invalid",
    )
    require(
        isinstance(value.get("prerequisite_families"), list)
        and all(isinstance(family, str) and family for family in value["prerequisite_families"]),
        "static product contract prerequisite_families are invalid",
    )
    return value


def validate_dynamic_product_contract() -> dict[str, Any]:
    """Validate the current product and any live reviewed qualification receipt."""
    report = dynamic_product.load_current_report()
    require(
        report.get("owner_family") == DYNAMIC_PRODUCT_GATE_ANCHOR,
        "dynamic product contract owner family is invalid",
    )
    require(
        report.get("status") in ("implemented-unqualified", "materialized"),
        "dynamic product contract cannot claim an unproved installed product",
    )
    for field in ("dynamic_family_ids", "prerequisite_families"):
        values = report.get(field)
        require(
            isinstance(values, list)
            and values
            and all(isinstance(value, str) and value for value in values),
            f"dynamic product contract {field} are invalid",
        )
    promotion = report.get("promotion")
    require(isinstance(promotion, Mapping), "dynamic product promotion state is invalid")
    require(
        promotion == {
            "family_completion": False,
            "promotion_ready": False,
            "public_support": False,
        },
        "dynamic product contract must remain non-promoting",
    )
    return report


def validate_routine_c_abi_matrix() -> dict[str, Any]:
    """Run the matrix's checked-generation contract and return its report."""
    document, sources = c_abi_matrix.load_matrix()
    outputs = c_abi_matrix.build_outputs(document, sources)
    # Keep this equivalent to the public ``--check`` command.  The report
    # should fail closed if a generated routine probe or its membership report
    # diverges from the approved matrix source.
    c_abi_matrix.check_outputs(outputs, ROOT)
    rendered = outputs[c_abi_matrix.GENERATED_DIRECTORY / "report.json"]
    value = json.loads(rendered)
    require(isinstance(value, dict), "generated C ABI matrix report is invalid")
    return value


def validate_qualification_manifest() -> dict[str, Any]:
    """Check the pinned qualification plan before exposing its aggregate gate.

    The qualification manifest is deliberately separate from the parity ledger:
    completed families name prerequisites, while a promotion chain must also
    pin immutable case manifests and receipts.  Checking its generated view
    here keeps a campaign report from describing a promotable qualification
    gate against stale or unpinned evidence state.
    """
    value = qualification_manifest.load_contract()
    qualification_manifest.write_or_check(
        qualification_manifest.GENERATED_PATH, value, check=True
    )
    promotion_chain = value.get("promotion_chain")
    require(isinstance(promotion_chain, list), "qualification manifest has no promotion chain")
    chain_ids = []
    for index, gate in enumerate(promotion_chain):
        require(isinstance(gate, Mapping), f"qualification manifest gate {index} is invalid")
        identifier = gate.get("id")
        require(
            isinstance(identifier, str) and identifier,
            f"qualification manifest gate {index} has an invalid id",
        )
        chain_ids.append(identifier)
    require(
        tuple(chain_ids) == QUALIFICATION_CHAIN,
        "qualification manifest promotion chain no longer matches the campaign roster",
    )
    incomplete_gates = value.get("incomplete_gates")
    require(
        isinstance(incomplete_gates, list)
        and all(isinstance(gate, str) and gate in QUALIFICATION_CHAIN for gate in incomplete_gates),
        "qualification manifest incomplete gate list is invalid",
    )
    require(
        isinstance(value.get("completed_gate_count"), int),
        "qualification manifest completed gate count is invalid",
    )
    require(
        isinstance(value.get("promotion_ready"), bool),
        "qualification manifest promotion readiness is invalid",
    )
    execution = value.get("execution")
    require(
        execution == qualification_manifest.EXECUTION_CONTRACT,
        "qualification manifest execution boundary is invalid",
    )
    require(
        execution["dispatcher_command"] == QUALIFICATION_RUNNER_COMMAND.split(),
        "qualification manifest dispatcher command is invalid",
    )
    return value


def validate_tls_runtime_v1_contract() -> dict[str, Any]:
    """Keep static/dynamic TLS ownership assumptions visible and fail-closed.

    The loader contract is implemented but unqualified unless its reviewed
    publication receipt validates against current source and every product.
    Private foundation evidence remains separate from this eligibility.
    """
    value = tls_runtime_v1.load_contract()
    require(
        value.get("status") in ("implemented-unqualified", "verified"),
        "loader/libc TLS RuntimeV1 contract cannot claim an unproved status",
    )
    require(
        value.get("runtime_v1_published") is (value.get("status") == "verified"),
        "loader/libc TLS RuntimeV1 contract cannot claim a published runtime",
    )
    process_modes = value.get("process_modes")
    require(
        process_modes == ["static", "dynamic"],
        "loader/libc TLS RuntimeV1 process-mode roster is invalid",
    )
    return value


def family_evidence_commands(family: Mapping[str, Any]) -> list[str]:
    """Return ledger-declared commands in stable order without inventing one."""
    evidence = family.get("native_evidence")
    require(isinstance(evidence, list), f"family {family.get('id')} native evidence is invalid")
    commands: list[str] = []
    for entry in evidence:
        require(isinstance(entry, Mapping), f"family {family.get('id')} native evidence entry is invalid")
        command = entry.get("command")
        require(isinstance(command, str) and command, f"family {family.get('id')} has an empty evidence command")
        if command not in commands:
            commands.append(command)
    return commands


def transitive_dependencies(
    family_id: str, families: Mapping[str, Mapping[str, Any]]
) -> list[str]:
    """Return dependency-order prerequisites, excluding ``family_id`` itself."""
    visited: set[str] = set()
    ordered: list[str] = []

    def visit(identifier: str) -> None:
        require(identifier in families, f"family {family_id} depends on unknown family {identifier}")
        dependencies = families[identifier].get("depends_on")
        require(isinstance(dependencies, list), f"family {identifier} dependencies are invalid")
        for dependency in dependencies:
            require(isinstance(dependency, str), f"family {identifier} has a non-string dependency")
            if dependency not in visited:
                visited.add(dependency)
                visit(dependency)
                ordered.append(dependency)

    visit(family_id)
    return ordered


def readiness(family: Mapping[str, Any], families: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Derive whether the ledger permits this family's next promotion step."""
    identifier = family.get("id")
    require(isinstance(identifier, str) and identifier, "family has an invalid id")
    status = family.get("status")
    require(isinstance(status, str) and status, f"family {identifier} has an invalid status")
    dependencies = family.get("depends_on")
    require(isinstance(dependencies, list), f"family {identifier} dependencies are invalid")
    blockers = [
        dependency
        for dependency in dependencies
        if dependency in families
        and families[dependency].get("status") != COMPLETED_STATUS
    ]
    if status == COMPLETED_STATUS:
        state = "complete"
    elif blockers:
        state = "blocked"
    else:
        state = "ready"
    return {"state": state, "blocking_dependencies": blockers}


def family_obligation(family: Mapping[str, Any], capability_rows: Iterable[Mapping[str, Any]]) -> dict[str, Any] | None:
    """Describe one still-open family transition without treating slices as closure."""
    if family.get("status") == COMPLETED_STATUS:
        return None
    identifier = family.get("id")
    require(isinstance(identifier, str) and identifier, "family has an invalid id")
    unresolved_capabilities = [
        row["id"]
        for row in capability_rows
        if row.get("x86_family") == identifier
        and row.get("contract_state") != "implemented-foundation"
    ]
    required_evidence = []
    evidence = family.get("native_evidence")
    require(isinstance(evidence, list), f"family {identifier} native evidence is invalid")
    for entry in evidence:
        require(isinstance(entry, Mapping), f"family {identifier} native evidence entry is invalid")
        if entry.get("state") != "verified":
            required_evidence.append(
                {
                    "command": entry.get("command"),
                    "scope": entry.get("scope"),
                    "state": entry.get("state"),
                }
            )
    return {
        "id": f"family-transition:{identifier}",
        "family": identifier,
        "description": family.get("description"),
        "unresolved_capabilities": unresolved_capabilities,
        "required_evidence": required_evidence,
    }


def gate_report(
    name: str,
    required_families: Iterable[str],
    families: Mapping[str, Mapping[str, Any]],
    *,
    has_machine_gate: bool,
    contract_status: str | None = None,
) -> dict[str, Any]:
    """Derive a gate state from family state; never assert successful promotion."""
    required = list(required_families)
    require(required, f"{name} gate has no required families")
    for family_id in required:
        require(family_id in families, f"{name} gate requires unknown family {family_id}")
    incomplete = [
        family_id
        for family_id in required
        if families[family_id].get("status") != COMPLETED_STATUS
    ]
    if incomplete:
        state = "blocked"
    elif not has_machine_gate:
        state = "unconfigured"
    elif contract_status is not None and contract_status != COMPLETED_STATUS:
        state = "ready"
    else:
        state = "passed"
    transitions = [
        {
            "family": family_id,
            "commands": family_evidence_commands(families[family_id]),
        }
        for family_id in incomplete
    ]
    return {
        "state": state,
        "required_families": required,
        "incomplete_families": incomplete,
        "transition_commands": transitions,
        "machine_gate_defined": has_machine_gate,
        "contract_status": contract_status,
        # This is a contract-derived result, not a remembered test outcome:
        # a machine gate passes only when every required family records its
        # promotion-recognized verified state.
        "pass": state == "passed",
    }


def build_report() -> dict[str, Any]:
    """Validate source contracts and derive the complete compact campaign view."""
    # The calls deliberately precede report construction: no status can be
    # emitted from stale AArch64 identity, malformed capability accounting, or
    # an invalid family dependency graph.
    (
        frozen_baseline,
        data,
        inventory_report,
        static_product_contract,
        dynamic_product_report,
        matrix_report,
        qualification_manifest_report,
        tls_runtime_v1_report,
    ) = load_validated_campaign_inputs()

    raw_families = data.get("family")
    promotion = data.get("promotion")
    require(isinstance(raw_families, list), "x86 parity ledger has no family list")
    require(isinstance(promotion, Mapping), "x86 parity ledger has no promotion table")
    required_family_ids = promotion.get("required_families")
    require(isinstance(required_family_ids, list), "x86 parity ledger promotion roster is invalid")
    families: dict[str, Mapping[str, Any]] = {}
    for family in raw_families:
        require(isinstance(family, Mapping), "x86 parity ledger family entry is invalid")
        identifier = family.get("id")
        require(isinstance(identifier, str) and identifier, "x86 parity ledger family id is invalid")
        families[identifier] = family
    require(list(families) == required_family_ids, "family order no longer matches the promotion roster")

    capability_rows = inventory_report.get("capabilities")
    require(isinstance(capability_rows, list), "derived parity inventory has no capabilities")
    require(
        all(isinstance(row, Mapping) for row in capability_rows),
        "derived parity inventory capability row is invalid",
    )
    capabilities = [dict(row) for row in capability_rows]

    family_rows: list[dict[str, Any]] = []
    obligations: list[dict[str, Any]] = []
    matrix_families = matrix_report.get("families")
    require(isinstance(matrix_families, list), "generated C ABI matrix has no family membership")
    matrix_membership: dict[str, Mapping[str, Any]] = {}
    for entry in matrix_families:
        require(isinstance(entry, Mapping), "generated C ABI matrix family entry is invalid")
        identifier = entry.get("id")
        require(isinstance(identifier, str) and identifier, "generated C ABI matrix family id is invalid")
        matrix_membership[identifier] = entry
    for family_id in required_family_ids:
        require(isinstance(family_id, str), "promotion roster has a non-string family id")
        family = families[family_id]
        family_readiness = readiness(family, families)
        row = {
            "id": family_id,
            "status": family.get("status"),
            "dependencies": list(family.get("depends_on", [])),
            "readiness": family_readiness,
            "commands": family_evidence_commands(family),
            "routine_c_abi_matrix": {
                "aggregate_command": matrix_membership.get(family_id, {}).get(
                    "aggregate_command"
                ),
                "row_ids": matrix_membership.get(family_id, {}).get("row_ids", []),
            },
            "transition": {
                "from": family.get("status"),
                "to": COMPLETED_STATUS,
                "commands": family_evidence_commands(family),
            },
        }
        family_rows.append(row)
        obligation = family_obligation(family, capabilities)
        if obligation is not None:
            obligations.append(obligation)

    static_anchor = static_product_contract["owner_family"]
    assert isinstance(static_anchor, str)
    dynamic_anchor = DYNAMIC_PRODUCT_GATE_ANCHOR
    static_requirements = list(static_product_contract["prerequisite_families"])
    assert all(isinstance(family, str) for family in static_requirements)
    if static_anchor not in static_requirements:
        static_requirements.append(static_anchor)
    declared_dynamic_families = [
        *dynamic_product_report["dynamic_family_ids"],
        *dynamic_product_report["prerequisite_families"],
    ]
    require(
        all(family_id in families for family_id in declared_dynamic_families),
        "dynamic product contract names an unknown x86 family",
    )
    dynamic_required_set: set[str] = set()
    for family_id in declared_dynamic_families:
        dynamic_required_set.update(transitive_dependencies(family_id, families))
        dynamic_required_set.add(family_id)
    dynamic_requirements = [
        family_id for family_id in required_family_ids if family_id in dynamic_required_set
    ]
    require(
        set(declared_dynamic_families).issubset(dynamic_requirements),
        "dynamic gate drops a product-declared prerequisite family",
    )
    tls_runtime_v1_eligible = (
        tls_runtime_v1_report["status"] == "verified"
        and tls_runtime_v1_report["runtime_v1_published"] is True
    )
    if tls_runtime_v1_eligible and dynamic_product_report["status"] == "materialized":
        require(
            tls_runtime_v1_report.get("qualification_source_sha256")
            == dynamic_product_report.get("qualification_source_sha256")
            and isinstance(dynamic_product_report.get("qualification_source_sha256"), str),
            "dynamic product and RuntimeV1 qualification sources differ",
        )
    dynamic_product_status = (
        COMPLETED_STATUS
        if dynamic_product_report["status"] == "materialized" and tls_runtime_v1_eligible
        else "planned"
    )
    static_product_status = str(static_product_contract["status"])
    qualification_requirements: list[str] = []
    for family_id in QUALIFICATION_CHAIN:
        for dependency in transitive_dependencies(family_id, families) + [family_id]:
            if dependency not in qualification_requirements:
                qualification_requirements.append(dependency)

    qualification_promotion_ready = qualification_manifest_report["promotion_ready"]
    assert isinstance(qualification_promotion_ready, bool)
    qualification_contract_status = (
        COMPLETED_STATUS if qualification_promotion_ready else "planned"
    )
    promotion_product_contract_status = (
        COMPLETED_STATUS
        if static_product_status == COMPLETED_STATUS
        and dynamic_product_status == COMPLETED_STATUS
        and qualification_contract_status == COMPLETED_STATUS
        else "planned"
    )
    qualification_chain = qualification_manifest_report["promotion_chain"]
    assert isinstance(qualification_chain, list)
    qualification_incomplete = qualification_manifest_report["incomplete_gates"]
    assert isinstance(qualification_incomplete, list)
    qualification_completed_count = qualification_manifest_report["completed_gate_count"]
    assert isinstance(qualification_completed_count, int)
    qualification_summary = {
        "contract_sha256": qualification_manifest_report.get("contract_sha256"),
        "promotion_chain": [gate["id"] for gate in qualification_chain],
        "completed_gate_count": qualification_completed_count,
        "incomplete_gates": list(qualification_incomplete),
        "promotion_ready": qualification_promotion_ready,
    }

    gates = {
        "static_product": {
            **gate_report(
                "static_product",
                static_requirements,
                families,
                has_machine_gate=True,
                contract_status=static_product_status,
            ),
            "owner_family": static_anchor,
            "modes": static_product_contract.get("mode"),
            "machine_gate_command": STATIC_PRODUCT_RUNNER_COMMAND,
        },
        "dynamic_product": {
            **gate_report(
                "dynamic_product",
                dynamic_requirements,
                families,
                has_machine_gate=True,
                contract_status=dynamic_product_status,
            ),
            "owner_family": dynamic_product_report["owner_family"],
            "product_state": dynamic_product_report["status"],
            "modes": dynamic_product_report["modes"],
            "coverage_obligations": dynamic_product_report["coverage_obligations"],
            "machine_gate_command": DYNAMIC_PRODUCT_RUNNER_COMMAND,
            "declared_family_requirements": declared_dynamic_families,
            "tls_runtime_v1_eligible": tls_runtime_v1_eligible,
        },
        "qualification": {
            **gate_report(
                "qualification",
                qualification_requirements,
                families,
                has_machine_gate=True,
                contract_status=qualification_contract_status,
            ),
            "machine_gate_command": QUALIFICATION_RUNNER_COMMAND,
            "manifest": qualification_summary,
        },
        "promotion": gate_report(
            "promotion",
            required_family_ids,
            families,
            has_machine_gate=False,
            contract_status=promotion_product_contract_status,
        ),
    }
    incomplete_capabilities = [
        row["id"]
        for row in capabilities
        if row.get("contract_state") != "implemented-foundation"
    ]
    promotion_ready = (
        gates["promotion"]["pass"]
        and gates["static_product"]["pass"]
        and gates["dynamic_product"]["pass"]
        and gates["qualification"]["pass"]
        and not incomplete_capabilities
    )

    next_transitions = [
        row["id"]
        for row in family_rows
        if row["readiness"]["state"] == "ready"
    ]
    capability_states = Counter(
        str(row.get("contract_state")) for row in capabilities
    )
    return {
        "schema": SCHEMA,
        "frozen_baseline": frozen_baseline,
        "campaign": {
            "target": data.get("target"),
            "platform": data.get("platform"),
            "public_support": data.get("policy", {}).get("public_support"),
            "promotion_ready": promotion_ready,
        },
        "validation": {
            "routine_c_abi_matrix_check": {
                "command": MATRIX_CHECK_COMMAND,
                "row_count": len(matrix_report.get("rows", [])),
            },
            "qualification_manifest_check": {
                "command": QUALIFICATION_MANIFEST_CHECK_COMMAND,
                "completed_gate_count": qualification_completed_count,
                "incomplete_gates": list(qualification_incomplete),
                "promotion_ready": qualification_promotion_ready,
            },
            "loader_libc_tls_runtime_v1_check": {
                "command": TLS_RUNTIME_V1_CHECK_COMMAND,
                "status": tls_runtime_v1_report["status"],
                "runtime_v1_published": tls_runtime_v1_report[
                    "runtime_v1_published"
                ],
                "process_modes": list(tls_runtime_v1_report["process_modes"]),
                "eligible_for_dynamic_product": tls_runtime_v1_eligible,
            },
            "dynamic_product_contract_check": {
                "command": DYNAMIC_PRODUCT_CONTRACT_CHECK_COMMAND,
                "status": dynamic_product_report["status"],
                "contract_sha256": dynamic_product_report["contract_sha256"],
                "coverage_obligations": dynamic_product_report[
                    "coverage_obligations"
                ],
                "dynamic_family_ids": list(dynamic_product_report["dynamic_family_ids"]),
                "prerequisite_families": list(
                    dynamic_product_report["prerequisite_families"]
                ),
            },
        },
        "state_counts": {
            "capabilities": dict(sorted(capability_states.items())),
            "families": dict(
                sorted(Counter(str(row["status"]) for row in family_rows).items())
            ),
        },
        "families": family_rows,
        "capabilities": capabilities,
        "unsatisfied_family_obligations": obligations,
        "gates": gates,
        "next_dependency_ready_transitions": [
            row for row in family_rows if row["id"] in next_transitions
        ],
    }


def select_family(report: Mapping[str, Any], family_id: str) -> dict[str, Any]:
    """Return a self-describing, filtered family report for dispatcher callers."""
    families = report.get("families")
    capabilities = report.get("capabilities")
    obligations = report.get("unsatisfied_family_obligations")
    require(isinstance(families, list), "report has no family rows")
    require(isinstance(capabilities, list), "report has no capability rows")
    require(isinstance(obligations, list), "report has no family obligations")
    family = next((row for row in families if row.get("id") == family_id), None)
    require(family is not None, f"unknown required family: {family_id}")
    return {
        "schema": SCHEMA,
        "frozen_baseline": report.get("frozen_baseline"),
        "campaign": report.get("campaign"),
        "family": family,
        "capabilities": [
            row for row in capabilities if row.get("x86_family") == family_id
        ],
        "unsatisfied_family_obligation": next(
            (row for row in obligations if row.get("family") == family_id), None
        ),
    }


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", metavar="ID", help="emit one required family")
    parser.add_argument("--output", type=Path, help="write canonical JSON to this path")
    arguments = parser.parse_args()
    report = build_report()
    if arguments.family is not None:
        report = select_family(report, arguments.family)
    output = canonical_json(report)
    if arguments.output is None:
        sys.stdout.write(output)
    else:
        arguments.output.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        CampaignReportError,
        dynamic_product.ProductContractError,
        c_abi_matrix.MatrixError,
        inventory.InventoryError,
        ledger.LedgerError,
        qualification_manifest.QualificationManifestError,
        tls_runtime_v1.TlsRuntimeContractError,
    ) as error:
        raise SystemExit(f"x86 campaign report: ERROR: {error}") from error
