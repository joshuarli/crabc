#!/usr/bin/env python3
"""Fail-closed native Linux/x86-64 gate for allocator Milestone 5.

M5 is "general persistent concurrency/lifecycle: pointer dispatch, remote
publication, generic exit, abandonment/reclaim/release, no forbidden
scaffolding, selected libc shadow, state auditing, deterministic and soak
churn, upstream pthread stress, and early codegen/performance proof"
(plan.md Milestones). The reviewed contract `m5-gate-x86_64-v3.5.0.json`
gives each of those conditions one gate and names the evidence it requires.

Evidence is one of three shapes:

* `native_tests`: `crabc-mimalloc/tests/native_*` integration targets, run
  together with their default-off audit and fault features. Every such
  target belongs to exactly one native evidence entry, so a new direct
  runtime witness cannot silently fall outside the milestone.
* `command`: an allocator-container command (`python3 <script> ...`). The
  one `{scratch}` placeholder names this run's fresh per-evidence directory.
* `command: null`: evidence that exists only outside this launcher (for
  example the runtime launcher's installed-sysroot suites). It is declared
  missing here, so a gate that depends on it must name a blocker.

A gate passes only when it carries no reviewed blocker and every evidence
entry executed successfully on this run. Runnable evidence is always
executed; its pass never removes a blocker by itself.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import run as harness


CONTRACT = harness.ALLOCATOR_ROOT / "m5-gate-x86_64-v3.5.0.json"
SCHEMA = "crabc-mimalloc-x86_64-m5-gate"
GATE_IDS = (
    "m5.pointer-dispatch",
    "m5.remote-publication",
    "m5.generic-exit",
    "m5.abandon-reclaim-release",
    "m5.no-forbidden-scaffolding",
    "m5.libc-shadow",
    "m5.state-auditing",
    "m5.churn-soak",
    "m5.upstream-stress",
    "m5.codegen-performance",
)
NATIVE_TESTS = harness.ROOT / "crabc-mimalloc/tests"
NATIVE_TEST_PREFIX = "native_"
NATIVE_FEATURES = "native-runtime-test-audit,native-runtime-test-fault"
RUST_TARGET = "x86_64-unknown-linux-musl"
EVIDENCE_TIMEOUT_SECONDS = 3600
SCRATCH_PLACEHOLDER = "{scratch}"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m5-gate"


def _string_list(value: object, subject: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or not all(isinstance(entry, str) and entry for entry in value)
        or len(set(value)) != len(value)
    ):
        raise harness.HarnessError(f"M5 gate {subject} must be a list of unique non-empty strings")
    return list(value)


def native_test_targets(tests_root: Path = NATIVE_TESTS) -> set[str]:
    """Every direct native runtime integration target in the crate."""

    return {path.stem for path in tests_root.glob(f"{NATIVE_TEST_PREFIX}*.rs")}


def native_test_command(targets: Sequence[str]) -> list[str]:
    """One Cargo run over the named native targets with their audit seams."""

    command = [
        "cargo", "test", "--locked", "--target", RUST_TARGET, "-p", "crabc-mimalloc",
        "--no-default-features", "--features", NATIVE_FEATURES, "--no-fail-fast",
    ]
    for target in targets:
        command += ["--test", target]
    return command


def validate_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str], native_targets: set[str]
) -> dict[str, Any]:
    """Validate gate identity, evidence honesty, and native-target closure."""

    if contract.get("schema") != SCHEMA or contract.get("format") != 1:
        raise harness.HarnessError("unsupported M5 allocator gate contract")
    upstream = contract.get("upstream")
    if not isinstance(upstream, Mapping) or dict(upstream) != {
        "version": pin["version"], "revision": pin["revision"],
    }:
        raise harness.HarnessError("M5 allocator gate upstream identity mismatch")

    evidence = contract.get("evidence")
    if not isinstance(evidence, Mapping) or not evidence:
        raise harness.HarnessError("M5 allocator gate lacks an evidence registry")
    runnable: dict[str, list[str]] = {}
    claimed: dict[str, str] = {}
    for evidence_id, record in evidence.items():
        if not isinstance(record, Mapping) or not isinstance(record.get("scope"), str) or not record["scope"]:
            raise harness.HarnessError(f"M5 evidence {evidence_id} lacks a scope")
        shape = set(record) - {"scope"}
        if shape == {"native_tests"}:
            targets = _string_list(record["native_tests"], f"evidence {evidence_id} native tests")
            for target in targets:
                if target not in native_targets:
                    raise harness.HarnessError(f"M5 evidence {evidence_id} names an absent native target: {target}")
                if target in claimed:
                    raise harness.HarnessError(
                        f"M5 native target {target} is claimed by both {claimed[target]} and {evidence_id}"
                    )
                claimed[target] = evidence_id
            runnable[evidence_id] = native_test_command(targets)
        elif shape == {"command"}:
            command = record["command"]
            if command is None:
                continue
            command = _string_list(command, f"evidence {evidence_id} command")
            if len(command) < 2 or command[0] != "python3" or not (harness.ROOT / command[1]).is_file():
                raise harness.HarnessError(f"M5 evidence {evidence_id} names an absent runner")
            if sum(argument.count(SCRATCH_PLACEHOLDER) for argument in command) > 1:
                raise harness.HarnessError(f"M5 evidence {evidence_id} names more than one scratch directory")
            runnable[evidence_id] = command
        else:
            raise harness.HarnessError(
                f"M5 evidence {evidence_id} must record scope with exactly native_tests or command"
            )
    unclaimed = sorted(native_targets - set(claimed))
    if unclaimed:
        raise harness.HarnessError(f"M5 evidence omits native integration targets: {unclaimed}")

    gates = contract.get("gates")
    if not isinstance(gates, list) or [
        gate.get("id") if isinstance(gate, Mapping) else None for gate in gates
    ] != list(GATE_IDS):
        raise harness.HarnessError("M5 allocator gate order or identity changed")
    referenced: set[str] = set()
    blocked: list[str] = []
    for gate in gates:
        gate_id = gate["id"]
        if set(gate) != {"id", "required", "acceptance", "evidence", "blocked_by"}:
            raise harness.HarnessError(f"M5 gate {gate_id} has unexpected fields")
        if gate["required"] is not True:
            raise harness.HarnessError(f"M5 gate {gate_id} must remain required")
        if not isinstance(gate["acceptance"], str) or not gate["acceptance"]:
            raise harness.HarnessError(f"M5 gate {gate_id} lacks an acceptance contract")
        gate_evidence = _string_list(gate["evidence"], f"{gate_id} evidence")
        unknown = [entry for entry in gate_evidence if entry not in evidence]
        if unknown:
            raise harness.HarnessError(f"M5 gate {gate_id} names undeclared evidence: {unknown}")
        referenced.update(gate_evidence)
        blockers = _string_list(gate["blocked_by"], f"{gate_id} blockers", allow_empty=True)
        if any(entry not in runnable for entry in gate_evidence) and not blockers:
            raise harness.HarnessError(f"M5 gate {gate_id} depends on missing evidence without a blocker")
        if blockers:
            blocked.append(gate_id)
    unreferenced = sorted(set(evidence) - referenced)
    if unreferenced:
        raise harness.HarnessError(f"M5 evidence is declared but unused: {unreferenced}")
    return {
        "blocked_gate_ids": blocked,
        "gate_ids": list(GATE_IDS),
        "missing_evidence": sorted(set(evidence) - set(runnable)),
        "native_target_count": len(claimed),
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


def run_evidence(runnable: Mapping[str, Sequence[str]], artifacts: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for evidence_id, command in runnable.items():
        name = evidence_id.replace(":", "-")
        # Evidence that refuses to overwrite its own receipt gets a directory
        # that this gate run alone owns.
        scratch = artifacts / name
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True)
        command = [argument.replace(SCRATCH_PLACEHOLDER, str(scratch)) for argument in command]
        record = harness.command_record(command, cwd=harness.ROOT, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
        log = artifacts / f"{name}.log"
        log.write_text(str(record["stdout"]) + str(record["stderr"]))
        results[evidence_id] = {
            "command": list(command),
            "log": harness.relative(log),
            "status": "passed" if record["status"] == 0 else "failed",
        }
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
        help="validate the contract and native-target closure without executing evidence")
    mode.add_argument("--gate", choices=GATE_IDS,
        help="execute and classify only the evidence of one gate")
    arguments = parser.parse_args(argv)
    contract = harness.read_json(CONTRACT)
    summary = validate_contract(contract, harness.load_pin(), native_test_targets())
    if arguments.check:
        print(
            f"M5 gate contract valid: {summary['native_target_count']} native targets in "
            f"{len(summary['gate_ids'])} gates; {len(summary['blocked_gate_ids'])} gates blocked; "
            f"{len(summary['missing_evidence'])} evidence entries missing"
        )
        return 0
    harness.require_native_x86_64()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    selected = contract
    runnable = summary["runnable_evidence"]
    if arguments.gate is not None:
        selected = dict(contract, gates=[gate for gate in contract["gates"] if gate["id"] == arguments.gate])
        wanted = set(selected["gates"][0]["evidence"])
        runnable = {key: value for key, value in runnable.items() if key in wanted}
    report = gate_report(selected, summary, run_evidence(runnable, ARTIFACTS))
    harness.write_json(ARTIFACTS / "report.json", report)
    for record in report["gates"]:
        print(f"{record['id']}: {record['status']}")
    if report["overall_status"] != "passed":
        print(
            f"M5 unmet: {len(report['unmet_required'])}/{len(report['gates'])} required gates; "
            f"report {harness.relative(ARTIFACTS / 'report.json')}",
            file=sys.stderr,
        )
        return 1
    print("M5 passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
