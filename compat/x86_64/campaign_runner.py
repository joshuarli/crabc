#!/usr/bin/env python3
"""Run one declared native x86 campaign aggregate without inventing evidence.

The campaign report is deliberately a state view.  This companion runner turns
one reported gate into an executable boundary only after the report proves its
family prerequisites complete and a machine gate exists.  Until then it emits
the report's exact blockers as JSON and exits unsuccessfully; it never starts
Docker merely to discover that the runtime is not ready.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import campaign_report


ROOT = Path(__file__).resolve().parents[2]
GATE_BY_COMMAND = {
    "static": "static_product",
    "dynamic": "dynamic_product",
    "qualification": "qualification",
    "promotion-check": "promotion",
}
ALL_GATE_ORDER = ("static_product", "dynamic_product", "qualification", "promotion")
PRODUCT_MACHINE_GATE_COMMANDS = {
    "static_product": campaign_report.STATIC_PRODUCT_RUNNER_COMMAND,
    "dynamic_product": campaign_report.DYNAMIC_PRODUCT_RUNNER_COMMAND,
}


class CampaignRunnerError(ValueError):
    """A report or registered native command is unsafe or incomplete."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CampaignRunnerError(message)


def report_gate(report: Mapping[str, Any], gate_name: str) -> Mapping[str, Any]:
    gates = report.get("gates")
    require(isinstance(gates, Mapping), "campaign report has no gates")
    gate = gates.get(gate_name)
    require(isinstance(gate, Mapping), f"campaign report has no {gate_name} gate")
    return gate


def blocker_payload(gate_name: str, gate: Mapping[str, Any]) -> dict[str, Any]:
    """Preserve report details rather than translating them into a stale summary."""
    return {
        "gate": gate_name,
        "state": gate.get("state"),
        "machine_gate_defined": gate.get("machine_gate_defined"),
        "incomplete_families": gate.get("incomplete_families"),
        "transition_commands": gate.get("transition_commands"),
    }


def verified_command_tokens(command: str) -> list[str]:
    """Accept only direct, repository-local command forms from the ledger."""
    try:
        tokens = shlex.split(command)
    except ValueError as error:
        raise CampaignRunnerError(f"invalid registered campaign command {command!r}: {error}") from error
    require(tokens, "registered campaign command is empty")
    executable = tokens[0]
    require(executable.startswith("./"), f"registered campaign command is not repository-local: {command}")
    relative = Path(executable)
    require(not relative.is_absolute() and ".." not in relative.parts, f"registered campaign command escapes repository: {command}")
    require((ROOT / relative).is_file(), f"registered campaign command executable is missing: {command}")
    require(not any(token in {"|", ";", "&&", "||", "<", ">"} for token in tokens), f"registered campaign command requires shell parsing: {command}")
    if executable == "./scripts/dev-x86_64.sh":
        require(len(tokens) >= 2, f"x86 dispatcher command has no subcommand: {command}")
        require(not tokens[1].startswith("campaign-"), f"campaign command recursively invokes itself: {command}")
    return tokens


def gate_commands(report: Mapping[str, Any], gate: Mapping[str, Any]) -> list[tuple[str, list[str]]]:
    """Resolve every gate family command in dependency order with de-duplication."""
    family_rows = report.get("families")
    required_families = gate.get("required_families")
    require(isinstance(family_rows, list), "campaign report has no family rows")
    require(isinstance(required_families, list), "campaign gate has no family requirements")
    families: dict[str, Mapping[str, Any]] = {}
    for family in family_rows:
        require(isinstance(family, Mapping), "campaign report has an invalid family row")
        identifier = family.get("id")
        require(isinstance(identifier, str) and identifier, "campaign report family id is invalid")
        families[identifier] = family

    commands: list[tuple[str, list[str]]] = []
    seen: set[str] = set()
    for family_id in required_families:
        require(isinstance(family_id, str) and family_id in families, "campaign gate names an unknown family")
        evidence = families[family_id].get("commands")
        require(isinstance(evidence, list), f"campaign family {family_id} has invalid command list")
        for command in evidence:
            require(isinstance(command, str) and command, f"campaign family {family_id} has an empty command")
            if command not in seen:
                seen.add(command)
                commands.append((family_id, verified_command_tokens(command)))
    require(commands, "completed campaign gate has no registered native evidence commands")
    return commands


def qualification_machine_gate_command(gate: Mapping[str, Any]) -> list[str]:
    """Return the one pinned terminal runner allowed for qualification.

    Family evidence establishes its prerequisites, but qualification itself is
    a separate receipt-pinned transaction.  Do not let a report field turn
    that final boundary into an arbitrary command invocation.
    """
    command = gate.get("machine_gate_command")
    require(
        command == campaign_report.QUALIFICATION_RUNNER_COMMAND,
        "qualification machine gate is not the pinned qualification runner",
    )
    tokens = shlex.split(campaign_report.QUALIFICATION_RUNNER_COMMAND)
    require(
        tokens == ["python3", "compat/x86_64/run_qualification_manifest.py"],
        "qualification runner command contract drifted",
    )
    runner = Path(tokens[1])
    require(
        not runner.is_absolute() and ".." not in runner.parts,
        "qualification runner command escapes repository",
    )
    require(
        (ROOT / runner).is_file(),
        "qualification runner is missing from the repository",
    )
    return tokens


def product_machine_gate_command(gate_name: str, gate: Mapping[str, Any]) -> list[str]:
    """Return the exact terminal runner for one owned product gate."""
    expected = PRODUCT_MACHINE_GATE_COMMANDS.get(gate_name)
    require(expected is not None, f"{gate_name} has no registered product machine gate")
    require(
        gate.get("machine_gate_command") == expected,
        f"{gate_name} machine gate is not the pinned {gate_name} runner",
    )
    return verified_command_tokens(expected)


def execute_terminal_machine_gate(gate_name: str, gate: Mapping[str, Any]) -> int:
    """Run the one explicitly registered terminal boundary for a passed gate."""
    if gate_name == "qualification":
        command = qualification_machine_gate_command(gate)
        label = "receipt-pinned machine gate"
    elif gate_name in PRODUCT_MACHINE_GATE_COMMANDS:
        command = product_machine_gate_command(gate_name, gate)
        label = "owned product machine gate"
    else:
        return 0
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        rendered = " ".join(shlex.quote(token) for token in command)
        print(
            f"x86 campaign {gate_name}: {label} failed "
            f"({completed.returncode}): {rendered}",
            file=sys.stderr,
        )
        return completed.returncode
    return 0


def execute_gate(report: Mapping[str, Any], gate_name: str) -> int:
    gate = report_gate(report, gate_name)
    if gate.get("pass") is not True:
        print(json.dumps(blocker_payload(gate_name, gate), indent=2, sort_keys=True))
        return 1

    for family_id, command in gate_commands(report, gate):
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode != 0:
            rendered = " ".join(shlex.quote(token) for token in command)
            print(
                f"x86 campaign {gate_name}: family {family_id} evidence failed "
                f"({completed.returncode}): {rendered}",
                file=sys.stderr,
            )
            return completed.returncode
    return execute_terminal_machine_gate(gate_name, gate)


def execute_all(report: Mapping[str, Any]) -> int:
    """Run gates in the contract's required order and stop at the first blocker."""
    for gate_name in ALL_GATE_ORDER:
        result = execute_gate(report, gate_name)
        if result != 0:
            return result
    return 0


def main(arguments: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=(*GATE_BY_COMMAND, "all"))
    parsed = parser.parse_args(arguments)
    try:
        report = campaign_report.build_report()
        if parsed.command == "all":
            return execute_all(report)
        return execute_gate(report, GATE_BY_COMMAND[parsed.command])
    except (CampaignRunnerError, campaign_report.CampaignReportError) as error:
        print(f"x86 campaign: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
