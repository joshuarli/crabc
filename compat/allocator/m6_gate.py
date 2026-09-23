#!/usr/bin/env python3
"""Fail-closed Milestone 6 gate for the native x86-64 mimalloc port.

M6 is complete only when every applicable Heap, Theap, arena, managed-memory,
and subprocess interface of pinned mimalloc v3.5.0 is implemented and its
destruction, cross-thread lifetime, and failure behavior is verified.  The
reviewed contract `m6-gate-v3.5.0.json` partitions that interface inventory
into gates and names the evidence each gate requires.

A gate passes only when it carries no reviewed blocker and every evidence
entry has a runner that executed successfully.  Evidence without a runner is
declared missing, and a gate that depends on it must name a blocker, so the
contract cannot claim completion that no executable check supports.  Runnable
evidence is always executed; its pass never removes a blocker by itself.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import run as harness


CONTRACT = harness.ALLOCATOR_ROOT / "m6-gate-v3.5.0.json"
SCHEMA = "crabc-mimalloc-m6-gate"
GATE_IDS = (
    "m6.heap-lifecycle",
    "m6.heap-membership",
    "m6.heap-allocation",
    "m6.heap-statistics-visitation",
    "m6.heap-source-conveniences",
    "m6.theap",
    "m6.arena",
    "m6.subprocess",
    "m6.destruction-lifetime",
    "m6.upstream",
)
# Cross-cutting gates own behavior rather than interface items.
ITEMLESS_GATE_IDS = frozenset({"m6.destruction-lifetime", "m6.upstream"})
EVIDENCE_TIMEOUT_SECONDS = 1800


def _string_list(value: object, subject: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or not all(isinstance(entry, str) and entry for entry in value)
        or len(set(value)) != len(value)
    ):
        raise harness.HarnessError(f"M6 gate {subject} must be a list of unique non-empty strings")
    return list(value)


def selected_inventory(inventory: Mapping[str, Any], api: Mapping[str, Any]) -> set[str]:
    """Return every applicable interface item the contract's selection rule names."""

    groups = set(_string_list(inventory.get("groups"), "inventory groups"))
    prefixes = tuple(_string_list(inventory.get("name_prefixes"), "inventory name prefixes"))
    additional = _string_list(inventory.get("additional_items"), "inventory additional items")
    items = api.get("items")
    if not isinstance(items, list):
        raise harness.HarnessError("M6 inventory authority lacks an item list")
    by_name: dict[str, Mapping[str, Any]] = {}
    for item in items:
        if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
            raise harness.HarnessError("M6 inventory authority has a malformed item")
        if item["name"] in by_name:
            raise harness.HarnessError(f"M6 inventory authority repeats {item['name']}")
        by_name[item["name"]] = item
    known_groups = {item.get("group") for item in by_name.values()}
    if not groups <= known_groups:
        raise harness.HarnessError(f"M6 inventory names unknown groups: {sorted(groups - known_groups)}")
    selected = {
        name
        for name, item in by_name.items()
        if item.get("target_applicability") == "applicable"
        and (item.get("group") in groups or name.startswith(prefixes))
    }
    for name in additional:
        item = by_name.get(name)
        if item is None:
            raise harness.HarnessError(f"M6 additional inventory item is absent: {name}")
        if item.get("target_applicability") != "applicable":
            raise harness.HarnessError(f"M6 additional inventory item is not applicable: {name}")
        if name in selected:
            raise harness.HarnessError(f"M6 additional inventory item is already selected: {name}")
        selected.add(name)
    return selected


def validate_contract(
    contract: Mapping[str, Any], api: Mapping[str, Any], pin: Mapping[str, str]
) -> dict[str, Any]:
    """Validate inventory closure and evidence honesty without claiming a pass."""

    if contract.get("schema") != SCHEMA or contract.get("format") != 1:
        raise harness.HarnessError("unsupported M6 allocator gate contract")
    upstream = contract.get("upstream")
    if not isinstance(upstream, Mapping) or dict(upstream) != {
        "version": pin["version"], "revision": pin["revision"],
    }:
        raise harness.HarnessError("M6 allocator gate upstream identity mismatch")
    if (api.get("mimalloc_version"), api.get("pinned_revision")) != (pin["version"], pin["revision"]):
        raise harness.HarnessError("M6 inventory authority upstream identity mismatch")
    inventory = contract.get("inventory")
    if not isinstance(inventory, Mapping) or inventory.get("authority") != harness.relative(
        harness.ALLOCATOR_ROOT / "api-v3.5.0.json"
    ):
        raise harness.HarnessError("M6 allocator gate must use the pinned API applicability inventory")
    selected = selected_inventory(inventory, api)

    evidence = contract.get("evidence")
    if not isinstance(evidence, Mapping) or not evidence:
        raise harness.HarnessError("M6 allocator gate lacks an evidence registry")
    runnable: dict[str, str] = {}
    for evidence_id, record in evidence.items():
        if not isinstance(record, Mapping) or set(record) != {"runner", "scope"}:
            raise harness.HarnessError(f"M6 evidence {evidence_id} must record exactly runner and scope")
        if not isinstance(record["scope"], str) or not record["scope"]:
            raise harness.HarnessError(f"M6 evidence {evidence_id} lacks a scope")
        runner = record["runner"]
        if runner is None:
            continue
        if not isinstance(runner, str) or not (harness.ROOT / runner).is_file():
            raise harness.HarnessError(f"M6 evidence {evidence_id} names an absent runner")
        runnable[evidence_id] = runner

    gates = contract.get("gates")
    if not isinstance(gates, list) or [
        gate.get("id") if isinstance(gate, Mapping) else None for gate in gates
    ] != list(GATE_IDS):
        raise harness.HarnessError("M6 allocator gate order or identity changed")
    assigned: dict[str, str] = {}
    referenced: set[str] = set()
    blocked: list[str] = []
    for gate in gates:
        gate_id = gate["id"]
        if set(gate) != {"id", "required", "items", "acceptance", "evidence", "blocked_by"}:
            raise harness.HarnessError(f"M6 gate {gate_id} has unexpected fields")
        if gate["required"] is not True:
            raise harness.HarnessError(f"M6 gate {gate_id} must remain required")
        if not isinstance(gate["acceptance"], str) or not gate["acceptance"]:
            raise harness.HarnessError(f"M6 gate {gate_id} lacks an acceptance contract")
        items = _string_list(gate["items"], f"{gate_id} items", allow_empty=gate_id in ITEMLESS_GATE_IDS)
        if gate_id in ITEMLESS_GATE_IDS and items:
            raise harness.HarnessError(f"M6 cross-cutting gate {gate_id} owns no interface items")
        for name in items:
            if name in assigned:
                raise harness.HarnessError(f"M6 item {name} is owned by both {assigned[name]} and {gate_id}")
            if name not in selected:
                raise harness.HarnessError(f"M6 gate {gate_id} names an unselected item: {name}")
            assigned[name] = gate_id
        gate_evidence = _string_list(gate["evidence"], f"{gate_id} evidence")
        unknown = [entry for entry in gate_evidence if entry not in evidence]
        if unknown:
            raise harness.HarnessError(f"M6 gate {gate_id} names undeclared evidence: {unknown}")
        referenced.update(gate_evidence)
        blockers = _string_list(gate["blocked_by"], f"{gate_id} blockers", allow_empty=True)
        if any(entry not in runnable for entry in gate_evidence) and not blockers:
            raise harness.HarnessError(f"M6 gate {gate_id} depends on missing evidence without a blocker")
        if blockers:
            blocked.append(gate_id)
    unassigned = sorted(selected - set(assigned))
    if unassigned:
        raise harness.HarnessError(f"M6 gates omit applicable inventory items: {unassigned}")
    unreferenced = sorted(set(evidence) - referenced)
    if unreferenced:
        raise harness.HarnessError(f"M6 evidence is declared but unused: {unreferenced}")
    return {
        "blocked_gate_ids": blocked,
        "gate_ids": list(GATE_IDS),
        "item_count": len(selected),
        "missing_evidence": sorted(set(evidence) - set(runnable)),
        "runnable_evidence": dict(sorted(runnable.items())),
    }


def gate_report(
    contract: Mapping[str, Any], summary: Mapping[str, Any], results: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Classify each gate from reviewed blockers and executed evidence."""

    records: list[dict[str, Any]] = []
    for gate in contract["gates"]:
        observed = {entry: results[entry]["status"] for entry in gate["evidence"] if entry in results}
        missing = [entry for entry in gate["evidence"] if entry not in summary["runnable_evidence"]]
        if any(status != "passed" for status in observed.values()):
            status = "failed"
        elif gate["blocked_by"] or missing or len(observed) != len(gate["evidence"]):
            status = "blocked"
        else:
            status = "passed"
        records.append({
            "blocked_by": list(gate["blocked_by"]),
            "evidence": observed,
            "id": gate["id"],
            "item_count": len(gate["items"]),
            "missing_evidence": missing,
            "status": status,
        })
    unmet = [record["id"] for record in records if record["status"] != "passed"]
    return {
        "contract": harness.relative(CONTRACT),
        "evidence": {key: dict(value) for key, value in sorted(results.items())},
        "gates": records,
        "item_count": summary["item_count"],
        "overall_status": "passed" if not unmet else "unmet",
        "unmet_required": unmet,
    }


def run_evidence(runnable: Mapping[str, str], artifacts: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for evidence_id, runner in runnable.items():
        record = harness.command_record(
            ["python3", runner], cwd=harness.ROOT, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS,
        )
        log = artifacts / f"{evidence_id.replace(':', '-')}.log"
        log.write_text(str(record["stdout"]) + str(record["stderr"]))
        results[evidence_id] = {
            "log": harness.relative(log),
            "runner": runner,
            "status": "passed" if record["status"] == 0 else "failed",
        }
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
        help="validate the contract and inventory closure without executing evidence")
    arguments = parser.parse_args(argv)
    pin = harness.load_pin()
    contract = harness.read_json(CONTRACT)
    summary = validate_contract(contract, harness.read_json(harness.ALLOCATOR_ROOT / "api-v3.5.0.json"), pin)
    if arguments.check:
        print(
            f"M6 gate contract valid: {summary['item_count']} interface items in "
            f"{len(summary['gate_ids'])} gates; {len(summary['blocked_gate_ids'])} gates blocked; "
            f"{len(summary['missing_evidence'])} evidence entries missing"
        )
        return 0
    harness.require_native_x86_64()
    artifacts = harness.ARTIFACT_ROOT / "x86_64/m6-gate"
    artifacts.mkdir(parents=True, exist_ok=True)
    report = gate_report(contract, summary, run_evidence(summary["runnable_evidence"], artifacts))
    harness.write_json(artifacts / "report.json", report)
    for record in report["gates"]:
        print(f"{record['id']}: {record['status']}")
    if report["overall_status"] != "passed":
        print(
            f"M6 unmet: {len(report['unmet_required'])}/{len(report['gates'])} required gates; "
            f"report {harness.relative(artifacts / 'report.json')}",
            file=sys.stderr,
        )
        return 1
    print("M6 passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
