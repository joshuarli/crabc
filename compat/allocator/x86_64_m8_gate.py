#!/usr/bin/env python3
"""Fail-closed native Linux/x86-64 gate for allocator Milestone 8.

M8 is "complete owned-libc integration: startup/constructors,
pthread/TSD/cleanup/cancellation/fork, errno/C ABI, weak/interposed symbols,
static/dynamic products, DSOs/loader, Rust std, Lua, and the selected
real-program corpus" (plan.md Milestones). The reviewed contract
`m8-gate-x86_64-v3.5.0.json` names, for each of those rows, the installed
native-shadow product evidence it requires.

Every evidence entry is an existing `scripts/dev-x86_64.sh` product command.
One entry, named by the contract's `products` record, builds the native-shadow
static and dynamic sysroots; the entries that consume supplied products
receive them through the `{static_sysroot}`/`{dynamic_sysroot}` placeholders,
bound from that entry's printed evidence directory. A consumer whose products
were not built does not run and is recorded as failed.

A gate passes only when it carries no reviewed blocker and every evidence
entry has a command that executed successfully on this run. Evidence without a
command is declared missing, and a gate that depends on it must name a
blocker. Runnable evidence is always executed; its pass never removes a
blocker by itself.

The product commands start their own containers, so this runner executes on
the native x86-64 host, not inside the allocator evidence image.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import run as harness


CONTRACT = harness.ALLOCATOR_ROOT / "m8-gate-x86_64-v3.5.0.json"
SCHEMA = "crabc-mimalloc-x86_64-m8-gate"
GATE_IDS = (
    "m8.startup-constructors",
    "m8.threads-fork",
    "m8.errno-c-abi",
    "m8.weak-interposed",
    "m8.static-dynamic-products",
    "m8.dso-loader",
    "m8.rust-std",
    "m8.lua",
    "m8.corpus",
)
PRODUCT_PLACEHOLDERS = ("{static_sysroot}", "{dynamic_sysroot}")
DISPATCHER = "scripts/dev-x86_64.sh"
EVIDENCE_TIMEOUT_SECONDS = 7200
# The dispatcher's container sees the checkout at this path.
CONTAINER_ROOT = Path("/workspace")
ARTIFACTS = harness.ROOT / ".work/allocator-x86_64/reports/allocator/x86_64/m8-gate"


def _string_list(value: object, subject: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or not all(isinstance(entry, str) and entry for entry in value)
        or len(set(value)) != len(value)
    ):
        raise harness.HarnessError(f"M8 gate {subject} must be a list of unique non-empty strings")
    return list(value)


def _uses_products(command: Sequence[str]) -> bool:
    return any(placeholder in argument for argument in command for placeholder in PRODUCT_PLACEHOLDERS)


def validate_contract(contract: Mapping[str, Any], pin: Mapping[str, str]) -> dict[str, Any]:
    """Validate the evidence registry and gate honesty without claiming a pass."""

    if contract.get("schema") != SCHEMA or contract.get("format") != 1:
        raise harness.HarnessError("unsupported M8 allocator gate contract")
    upstream = contract.get("upstream")
    if not isinstance(upstream, Mapping) or dict(upstream) != {
        "version": pin["version"], "revision": pin["revision"],
    }:
        raise harness.HarnessError("M8 allocator gate upstream identity mismatch")

    evidence = contract.get("evidence")
    if not isinstance(evidence, Mapping) or not evidence:
        raise harness.HarnessError("M8 allocator gate lacks an evidence registry")
    products = contract.get("products")
    if not isinstance(products, Mapping) or set(products) != {
        "evidence", "evidence_line", "static_sysroot", "dynamic_sysroot",
    } or not all(isinstance(value, str) and value for value in products.values()):
        raise harness.HarnessError("M8 products record must name its evidence, line prefix, and sysroot names")
    runnable: dict[str, list[str]] = {}
    for evidence_id, record in evidence.items():
        if not isinstance(record, Mapping) or set(record) != {"command", "scope"}:
            raise harness.HarnessError(f"M8 evidence {evidence_id} must record exactly command and scope")
        if not isinstance(record["scope"], str) or not record["scope"]:
            raise harness.HarnessError(f"M8 evidence {evidence_id} lacks a scope")
        command = record["command"]
        if command is None:
            continue
        command = _string_list(command, f"evidence {evidence_id} command")
        if len(command) < 2 or command[0] != DISPATCHER or not (harness.ROOT / command[0]).is_file():
            raise harness.HarnessError(f"M8 evidence {evidence_id} must be a {DISPATCHER} product command")
        runnable[evidence_id] = command
    producer = products["evidence"]
    if producer not in runnable:
        raise harness.HarnessError("M8 products evidence must be runnable")
    if _uses_products(runnable[producer]):
        raise harness.HarnessError("M8 products evidence cannot consume its own products")

    gates = contract.get("gates")
    if not isinstance(gates, list) or [
        gate.get("id") if isinstance(gate, Mapping) else None for gate in gates
    ] != list(GATE_IDS):
        raise harness.HarnessError("M8 allocator gate order or identity changed")
    referenced: set[str] = set()
    blocked: list[str] = []
    for gate in gates:
        gate_id = gate["id"]
        if set(gate) != {"id", "required", "acceptance", "evidence", "blocked_by"}:
            raise harness.HarnessError(f"M8 gate {gate_id} has unexpected fields")
        if gate["required"] is not True:
            raise harness.HarnessError(f"M8 gate {gate_id} must remain required")
        if not isinstance(gate["acceptance"], str) or not gate["acceptance"]:
            raise harness.HarnessError(f"M8 gate {gate_id} lacks an acceptance contract")
        gate_evidence = _string_list(gate["evidence"], f"{gate_id} evidence")
        unknown = [entry for entry in gate_evidence if entry not in evidence]
        if unknown:
            raise harness.HarnessError(f"M8 gate {gate_id} names undeclared evidence: {unknown}")
        referenced.update(gate_evidence)
        blockers = _string_list(gate["blocked_by"], f"{gate_id} blockers", allow_empty=True)
        if any(entry not in runnable for entry in gate_evidence) and not blockers:
            raise harness.HarnessError(f"M8 gate {gate_id} depends on missing evidence without a blocker")
        if blockers:
            blocked.append(gate_id)
    unreferenced = sorted(set(evidence) - referenced)
    if unreferenced:
        raise harness.HarnessError(f"M8 evidence is declared but unused: {unreferenced}")
    return {
        "blocked_gate_ids": blocked,
        "gate_ids": list(GATE_IDS),
        "missing_evidence": sorted(set(evidence) - set(runnable)),
        "products": dict(products),
        "runnable_evidence": runnable,
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
            "missing_evidence": missing,
            "status": status,
        })
    unmet = [record["id"] for record in records if record["status"] != "passed"]
    return {
        "contract": harness.relative(CONTRACT),
        "evidence": {key: dict(value) for key, value in sorted(results.items())},
        "gates": records,
        "overall_status": "passed" if not unmet else "unmet",
        "unmet_required": unmet,
    }


def product_directory(output: str, line_prefix: str) -> str | None:
    """The evidence directory the products command printed, if exactly one."""

    found = [line[len(line_prefix):].strip() for line in output.splitlines() if line.startswith(line_prefix)]
    if len(found) != 1 or not found[0].startswith(f"{CONTAINER_ROOT}/"):
        return None
    return found[0]


def bind_products(command: Sequence[str], products: Mapping[str, str], directory: str) -> list[str]:
    """Replace the sysroot placeholders with the built products' container paths."""

    static = f"{directory}/{products['static_sysroot']}"
    dynamic = f"{directory}/{products['dynamic_sysroot']}"
    return [
        argument.replace("{static_sysroot}", static).replace("{dynamic_sysroot}", dynamic)
        for argument in command
    ]


def ordered_evidence(runnable: Mapping[str, Sequence[str]], producer: str) -> list[str]:
    """The products command first, then every other entry in contract order."""

    return [producer, *(entry for entry in runnable if entry != producer)]


def run_evidence(
    runnable: Mapping[str, Sequence[str]], products: Mapping[str, str], selected: Sequence[str], artifacts: Path,
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    directory: str | None = None
    producer = products["evidence"]
    for evidence_id in ordered_evidence(runnable, producer):
        command = runnable[evidence_id]
        needs_products = _uses_products(command)
        if evidence_id not in selected and not (evidence_id == producer and any(
            _uses_products(runnable[entry]) for entry in selected
        )):
            continue
        log = artifacts / f"{evidence_id.replace(':', '-')}.log"
        if needs_products:
            if directory is None:
                log.write_text(f"not run: {producer} did not provide native-shadow products\n")
                results[evidence_id] = {"command": list(command), "log": harness.relative(log), "status": "failed"}
                continue
            command = bind_products(command, products, directory)
        record = harness.command_record(
            [str(harness.ROOT / command[0]), *command[1:]], cwd=harness.ROOT,
            timeout_seconds=EVIDENCE_TIMEOUT_SECONDS,
        )
        log.write_text(str(record["stdout"]) + str(record["stderr"]))
        passed = record["status"] == 0
        if evidence_id == producer and passed:
            directory = product_directory(str(record["stdout"]) + str(record["stderr"]), products["evidence_line"])
            passed = directory is not None
        if evidence_id in selected:
            results[evidence_id] = {
                "command": list(command),
                "log": harness.relative(log),
                "status": "passed" if passed else "failed",
            }
    return results


def load_summary() -> tuple[dict[str, Any], dict[str, Any]]:
    contract = harness.read_json(CONTRACT)
    return contract, validate_contract(contract, harness.load_pin())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
        help="validate the contract without executing evidence")
    mode.add_argument("--gate", choices=GATE_IDS, help="execute only this gate's runnable evidence")
    arguments = parser.parse_args(argv)
    contract, summary = load_summary()
    if arguments.check:
        print(
            f"M8 gate contract valid: {len(summary['gate_ids'])} gates; "
            f"{len(summary['blocked_gate_ids'])} gates blocked; "
            f"{len(summary['missing_evidence'])} evidence entries missing"
        )
        return 0
    harness.require_native_x86_64()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    runnable = summary["runnable_evidence"]
    selected = list(runnable)
    if arguments.gate is not None:
        gate = next(entry for entry in contract["gates"] if entry["id"] == arguments.gate)
        selected = [entry for entry in gate["evidence"] if entry in runnable]
        contract = {**contract, "gates": [gate]}
    report = gate_report(contract, summary, run_evidence(runnable, summary["products"], selected, ARTIFACTS))
    report_path = ARTIFACTS / ("report.json" if arguments.gate is None else f"{arguments.gate}.json")
    harness.write_json(report_path, report)
    for record in report["gates"]:
        print(f"{record['id']}: {record['status']}")
        for evidence_id, status in record["evidence"].items():
            print(f"  {evidence_id}: {status}")
        for blocker in record["blocked_by"]:
            print(f"  blocked: {blocker}")
        for evidence_id in record["missing_evidence"]:
            print(f"  missing: {evidence_id}")
    if report["overall_status"] != "passed":
        print(
            f"M8 unmet: {len(report['unmet_required'])}/{len(report['gates'])} required gates; "
            f"report {harness.relative(report_path)}",
            file=sys.stderr,
        )
        return 1
    print("M8 passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
