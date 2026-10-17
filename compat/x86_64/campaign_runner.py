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
import hashlib
import json
import os
import shlex
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import campaign_report


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
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
    payload = {
        "gate": gate_name,
        "state": gate.get("state"),
        "machine_gate_defined": gate.get("machine_gate_defined"),
        "incomplete_families": gate.get("incomplete_families"),
        "transition_commands": gate.get("transition_commands"),
    }
    if gate_name == "qualification":
        payload["chain_conditions"] = qualification_chain_conditions(gate["manifest"]["qualification_profile"])
    return payload


def qualification_chain_conditions(profile: str) -> list[dict[str, Any]]:
    """Name every ordered gate's unmet declared conditions without Docker.

    Host evaluation covers prerequisite families, reader registration and
    checked-in completion checks. Reader rows that need the pinned image stay
    listed as native reads; they cannot pass here.
    """
    import qualification_gates

    rows = []
    for result in qualification_gates.evaluate_chain(native=False, profile=profile):
        rows.append(
            {
                "gate": result["gate"],
                "unmet": [row for row in result["conditions"] if row["met"] is False],
                "native_reads": [row["id"] for row in result["conditions"] if row["met"] is None],
            }
        )
    return rows


def require_repository_file(relative: Path, description: str) -> None:
    """Keep registered execution targets on physical checkout paths."""
    require(not relative.is_absolute() and ".." not in relative.parts,
            f"{description} escapes repository")
    path = ROOT
    for part in relative.parts:
        path /= part
        require(not path.is_symlink(), f"{description} crosses a symlink: {relative}")
    require(path.is_file(), f"{description} is missing from the repository: {relative}")


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
    require_repository_file(relative, "registered campaign command executable")
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
        tokens == ["./scripts/dev-x86_64.sh", "qualification-manifest"],
        "qualification runner command contract drifted",
    )
    scope = gate.get("manifest")
    require(isinstance(scope, Mapping), "qualification gate has no profile scope")
    profile = scope.get("qualification_profile")
    try:
        active = campaign_report.qualification_manifest.active_chain(profile)
        deferred = campaign_report.qualification_manifest.deferred_gate_ids(profile)
    except campaign_report.qualification_manifest.QualificationManifestError as error:
        raise CampaignRunnerError(str(error)) from error
    require(scope.get("active_gate_ids") == list(active) and scope.get("deferred_gate_ids") == list(deferred),
            "qualification gate profile scope drifted")
    return verified_command_tokens(campaign_report.QUALIFICATION_RUNNER_COMMAND) + ["--profile", profile]


def product_machine_gate_command(gate_name: str, gate: Mapping[str, Any]) -> list[str]:
    """Return the exact terminal runner for one owned product gate."""
    expected = PRODUCT_MACHINE_GATE_COMMANDS.get(gate_name)
    require(expected is not None, f"{gate_name} has no registered product machine gate")
    require(
        gate.get("machine_gate_command") == expected,
        f"{gate_name} machine gate is not the pinned {gate_name} runner",
    )
    return verified_command_tokens(expected)


def promotion_work_path(value: str | Path) -> Path:
    path = Path(value)
    if str(path).startswith('/workspace/'):
        path = ROOT / path.relative_to('/workspace')
    elif not path.is_absolute():
        path = ROOT / path
    require('..' not in path.parts and path.is_relative_to(ROOT / '.work')
            and path.resolve() == path and path.exists(), 'promotion input is not a physical checkout work path')
    return path


def promotion_input_snapshot(receipt: Path) -> dict:
    """Freeze concrete inputs across the two image-owned validation phases."""
    import campaign_promotion_closure as closure

    allocator = ROOT / '.work/allocator-x86_64'
    roots = {promotion_work_path(receipt).parent,
             promotion_work_path(allocator / 'reports/allocator/x86_64'),
             promotion_work_path(allocator / 'target/compat/allocator/x86_64'),
             promotion_work_path(allocator / 'integrated'), promotion_work_path(allocator / 'm10-native'),
             promotion_work_path(allocator / 'allocator-cache')}
    for pointer in (ROOT / '.work/x86_64/owned-static-qualification.json',
                    ROOT / '.work/x86_64/owned-dynamic-qualification.json',
                    ROOT / '.work/x86_64/qualification-evidence/performance.release/performance-release.json'):
        roots.add(promotion_work_path(pointer))
        selection = json.loads(pointer.read_text())
        selected = promotion_work_path(selection['receipt'])
        roots.add(selected.parent)
        document = json.loads(selected.read_text())
        if 'work' in document:
            roots.add(promotion_work_path(document['work']))
        def inputs(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == 'path' and isinstance(item, str) and (
                            item.startswith(('.work/', '/workspace/.work/', str(ROOT / '.work') + '/'))):
                        roots.add(promotion_work_path(item))
                    else:
                        inputs(item)
            elif isinstance(value, list):
                for item in value:
                    inputs(item)
        inputs(document.get('inputs', {}))
    sealed = {}
    for root in sorted(roots):
        digest = hashlib.sha256()
        for path in [root, *sorted(root.rglob('*'))] if root.is_dir() else [root]:
            stat = path.lstat()
            digest.update(path.relative_to(ROOT).as_posix().encode() + b'\0')
            digest.update(f'{stat.st_mode}:{stat.st_mtime_ns}:{stat.st_ctime_ns}'.encode() + b'\0')
            if path.is_symlink():
                require(path.resolve().is_relative_to(ROOT / '.work'), 'promotion input link escapes work storage')
                digest.update(os.readlink(path).encode() + b'\0')
                if path.resolve().is_file():
                    digest.update(hashlib.sha256(path.read_bytes()).digest())
            elif path.is_file():
                with path.open('rb') as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
            else:
                require(path.is_dir(), 'promotion input contains a special file')
        sealed[root.relative_to(ROOT).as_posix()] = digest.hexdigest()
    return {'source': closure.qualification.source_identity(), 'inputs': sealed}


def execute_native_promotion(core_command: list[str], receipt: Path) -> int:
    """Join image-owned readers only while their concrete inputs stay unchanged."""
    receipt = promotion_work_path(receipt)
    before = promotion_input_snapshot(receipt)
    core = subprocess.run(core_command, cwd=ROOT, check=False, capture_output=True, text=True)
    if core.returncode != 3:
        print(core.stdout, end='')
        print(core.stderr, end='', file=sys.stderr)
        require(False, 'native CORE phase did not return its pending allocator result')
    partial = json.loads(core.stdout)
    require(set(partial) == {'qualification_profile', 'source', 'qualification_receipt',
                            'functional_readiness', 'native_allocator_pending',
                            'allocator_qualification_profile', 'public_support'}
            and partial['qualification_profile'] == 'full'
            and partial['functional_readiness'] is False and partial['native_allocator_pending'] is True
            and partial['source'] == before['source']
            and partial['qualification_receipt'] == '/workspace/' + receipt.relative_to(ROOT).as_posix()
            and partial['allocator_qualification_profile'] in {'baseline', 'full'}
            and type(partial['public_support']) is bool,
            'native CORE phase result differs from its expected partial contract')
    require(promotion_input_snapshot(receipt) == before, 'promotion inputs changed after CORE validation')
    profile = partial['allocator_qualification_profile']
    command = ['./compat/allocator/run-x86_64.sh', 'allocator-m9', '--profile', profile, '--validate-retained']
    allocator = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
    if allocator.returncode != 0:
        print(allocator.stdout, end='')
        print(allocator.stderr, end='', file=sys.stderr)
        return allocator.returncode
    result = json.loads(allocator.stdout)
    report = ROOT / '.work/allocator-x86_64/target/compat/allocator/x86_64/m9-gate/report.json'
    require(set(result) == {'qualification_profile', 'report', 'report_sha256', 'source', 'm0'}
            and result['qualification_profile'] == profile and result['m0'] == 'checked'
            and result['report'] == report.relative_to(ROOT).as_posix()
            and result['report_sha256'] == hashlib.sha256(report.read_bytes()).hexdigest()
            and result['source'] == {'head': before['source']['revision'], 'clean': True, 'dirty_paths': []},
            'native allocator phase result lacks its current report and source binding')
    require(promotion_input_snapshot(receipt) == before, 'promotion source or inputs changed across image validation')
    terminal = subprocess.run(core_command, cwd=ROOT, check=False, capture_output=True, text=True)
    if terminal.returncode != 3:
        print(terminal.stdout, end='')
        print(terminal.stderr, end='', file=sys.stderr)
    require(terminal.returncode == 3 and json.loads(terminal.stdout) == partial,
            'terminal CORE owning readers refused current runtime evidence')
    require(promotion_input_snapshot(receipt) == before,
            'promotion source or inputs changed during terminal CORE validation')
    print('x86 campaign promotion closure: PASS (CORE runtime and ALLOC allocator readers)')
    return 0


def execute_terminal_machine_gate(gate_name: str, gate: Mapping[str, Any], qualification_receipt: Path | None = None) -> int:
    """Run the one explicitly registered terminal boundary for a passed gate."""
    if gate_name == "qualification":
        command = qualification_machine_gate_command(gate)
        label = "receipt-pinned machine gate"
    elif gate_name == "promotion":
        require(gate.get("machine_gate_command") == campaign_report.PROMOTION_RUNNER_COMMAND,
                "promotion machine gate is not the pinned closure reader")
        require(qualification_receipt is not None, "promotion requires an explicit qualification receipt")
        command = verified_command_tokens(campaign_report.PROMOTION_RUNNER_COMMAND) + ["--qualification-receipt", str(qualification_receipt)]
        from scripts import build_x86_64_owned_sysroot as builder
        if builder.DEFAULT_ALLOCATOR_BACKEND == 'native':
            return execute_native_promotion(command, qualification_receipt)
        label = "source-bound promotion closure reader"
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


def execute_gate(report: Mapping[str, Any], gate_name: str, qualification_receipt: Path | None = None) -> int:
    gate = report_gate(report, gate_name)
    if gate_name == "promotion" and gate.get("state") in {"ready", "passed"} and gate.get("machine_gate_defined") is True:
        return execute_terminal_machine_gate(gate_name, gate, qualification_receipt)
    if gate.get("pass") is not True:
        print(json.dumps(blocker_payload(gate_name, gate), indent=2, sort_keys=True))
        return 1
    if gate_name == "qualification":
        # Qualification is the ordered chain itself. Each gate re-reads its
        # own evidence against current source and checks its prerequisite
        # families; re-running every family's placeholder-bearing development
        # commands here would neither add proof nor be executable verbatim.
        return execute_terminal_machine_gate(gate_name, gate)

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


def execute_all(report: Mapping[str, Any], qualification_receipt: Path | None = None) -> int:
    """Run gates in the contract's required order and stop at the first blocker."""
    for gate_name in ALL_GATE_ORDER:
        result = execute_gate(report, gate_name, qualification_receipt)
        if result != 0:
            return result
    return 0


def main(arguments: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=(*GATE_BY_COMMAND, "all"))
    parser.add_argument("--qualification-receipt", type=Path, help="explicit current completed receipt for promotion-check or all")
    parsed = parser.parse_args(arguments)
    if parsed.qualification_receipt is not None and parsed.command not in {"promotion-check", "all"}:
        parser.error("qualification receipt applies only to promotion-check or all")
    try:
        report = campaign_report.build_report()
        if parsed.command == "all":
            return execute_all(report, parsed.qualification_receipt)
        return execute_gate(report, GATE_BY_COMMAND[parsed.command], parsed.qualification_receipt)
    except (CampaignRunnerError, campaign_report.CampaignReportError) as error:
        print(f"x86 campaign: ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
