#!/usr/bin/env python3
"""Fail-closed native Linux/x86-64 gate for allocator Milestone 7.

M7 is "all applicable options/environment, callbacks/deferred free,
statistics, visitation, debug, secure, guarded and optional ISA profiles,
without raising the baseline" (plan.md Milestones). The reviewed contract
`m7-gate-x86_64-v3.5.0.json` selects the M7 interface items and compile-time
modes from the pinned API applicability inventory, partitions them into
gates, and names the evidence each gate requires.

A gate passes only when it carries no reviewed blocker and every evidence
entry has a command that executed successfully on this run. Evidence without a
command is declared missing, and a gate that depends on it must name a
blocker, so the contract cannot claim completion that no executable check
supports. Runnable evidence is always executed; its pass never removes a
blocker by itself.

`--options-differential` and `--option-effects-differential` run the two
evidence checks this module owns. Each builds a pinned-C oracle
(`x86_64_m7_options_oracle.c`, `x86_64_m7_option_effects_oracle.c`) and runs
one exact Rust test (`diagnostic_output::tests::source_options_trace_...` and
`..._option_effects_trace_...`) in separate processes; both print the same
`key=value` trace, and every key must match.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import run as harness


CONTRACT = harness.ALLOCATOR_ROOT / "m7-gate-x86_64-v3.5.0.json"
SCHEMA = "crabc-mimalloc-x86_64-m7-gate"
GATE_IDS = (
    "m7.options-environment",
    "m7.option-effects",
    "m7.callbacks",
    "m7.statistics",
    "m7.visitation",
    "m7.debug",
    "m7.secure",
    "m7.guarded",
    "m7.optional-isa",
    "m7.baseline",
)
# Cross-cutting gates own behavior rather than interface items or modes.
ITEMLESS_GATE_IDS = frozenset({"m7.option-effects", "m7.visitation", "m7.baseline"})
EVIDENCE_TIMEOUT_SECONDS = 3600
# An evidence command argument may name this run's fresh per-evidence
# directory, for runners that refuse to replace an existing receipt.
SCRATCH_PLACEHOLDER = "{scratch}"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m7-gate"

OPTIONS_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_options_oracle.c"
OPTIONS_RUST_TEST = "diagnostic_output::tests::source_options_trace_for_pinned_c_comparison"
OPTIONS_TRACE_BEGIN = "CRABC_MI_M7_OPTIONS_TRACE_BEGIN"
OPTIONS_TRACE_END = "CRABC_MI_M7_OPTIONS_TRACE_END"
# Every environment image both halves must replay. A scenario absent from both
# traces would otherwise compare equal.
OPTIONS_SCENARIOS = (
    "empty", "canonical", "legacy", "invalid", "verbose", "guarded_boolean",
    "guarded_numeric", "size_without_digits", "cap", "overlong",
)
OPTIONS_ERROR_SCENARIOS = ("hidden", "capped", "verbose")
# Recursive-output scenarios: a registered callback that reads `verbose` and
# re-enters `_mi_warning_message` during startup and one direct warning.
OPTIONS_RECURSION_SCENARIOS = ("invalid_verbose", "show_errors", "capped")
ERROR_SITES_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_error_sites_oracle.c"
ERROR_SITES_RUST_TEST = "native_error_sites"
ERROR_SITES_TRACE_BEGIN = "CRABC_MI_M7_ERROR_SITES_TRACE_BEGIN"
ERROR_SITES_TRACE_END = "CRABC_MI_M7_ERROR_SITES_TRACE_END"
# Both halves run with the error gate open so every reached site is shown.
ERROR_SITES_ENVIRONMENT = {"mimalloc_show_errors": "1"}
# Every request both halves must report, on the main thread and a worker.
ERROR_SITE_CASES = tuple(
    prefix + case
    for prefix in ("", "worker_")
    for case in (
        "malloc_too_large", "aligned_bad_alignment", "aligned_too_large",
        "aligned_large_alignment_offset", "aligned_overallocation_too_large", "malloc_ordinary",
    )
)
OPTION_EFFECTS_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_option_effects_oracle.c"
OPTION_EFFECTS_RUST_TEST = "diagnostic_output::tests::source_option_effects_trace_for_pinned_c_comparison"
OPTION_EFFECTS_TRACE_BEGIN = "CRABC_MI_M7_OPTION_EFFECTS_TRACE_BEGIN"
OPTION_EFFECTS_TRACE_END = "CRABC_MI_M7_OPTION_EFFECTS_TRACE_END"
# Every decision family both halves must trace; a family absent from both
# traces would otherwise compare equal.
OPTION_EFFECT_FAMILIES = (
    "host", "arena_max_object_size", "arena_purge_delay", "minimal_purge_size",
    "numa_node_count", "generic_collect", "arena_reserve",
)
RUST_TARGET = "x86_64-unknown-linux-musl"


def _string_list(value: object, subject: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or not all(isinstance(entry, str) and entry for entry in value)
        or len(set(value)) != len(value)
    ):
        raise harness.HarnessError(f"M7 gate {subject} must be a list of unique non-empty strings")
    return list(value)


def _by_name(entries: object, subject: str) -> dict[str, Mapping[str, Any]]:
    if not isinstance(entries, list):
        raise harness.HarnessError(f"M7 inventory authority lacks its {subject} list")
    result: dict[str, Mapping[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("name"), str):
            raise harness.HarnessError(f"M7 inventory authority has a malformed {subject} entry")
        if entry["name"] in result:
            raise harness.HarnessError(f"M7 inventory authority repeats {entry['name']}")
        result[entry["name"]] = entry
    return result


def _select(
    by_name: Mapping[str, Mapping[str, Any]],
    key: str,
    categories: Sequence[str],
    additional: Sequence[str],
    subject: str,
) -> set[str]:
    """Select applicable authority entries by category plus named additions."""

    known = {entry.get(key) for entry in by_name.values()}
    unknown = sorted(set(categories) - known)
    if unknown:
        raise harness.HarnessError(f"M7 inventory names unknown {subject} categories: {unknown}")
    selected = {
        name for name, entry in by_name.items()
        if entry.get("target_applicability") == "applicable" and entry.get(key) in categories
    }
    for name in additional:
        entry = by_name.get(name)
        if entry is None:
            raise harness.HarnessError(f"M7 additional {subject} is absent: {name}")
        if entry.get("target_applicability") != "applicable":
            raise harness.HarnessError(f"M7 additional {subject} is not applicable: {name}")
        if name in selected:
            raise harness.HarnessError(f"M7 additional {subject} is already selected: {name}")
        selected.add(name)
    return selected


def selected_inventory(
    inventory: Mapping[str, Any], api: Mapping[str, Any]
) -> tuple[set[str], set[str]]:
    """Return the applicable interface items and compile-time modes M7 owns."""

    items = _select(
        _by_name(api.get("items"), "item"), "group",
        _string_list(inventory.get("groups"), "inventory groups"),
        _string_list(inventory.get("additional_items"), "inventory additional items"),
        "item",
    )
    modes = _select(
        _by_name(api.get("compile_time_modes"), "compile-time mode"), "classification",
        _string_list(inventory.get("mode_classifications"), "inventory mode classifications"),
        _string_list(inventory.get("additional_modes"), "inventory additional modes"),
        "mode",
    )
    return items, modes


def sibling_owned_items(inventory: Mapping[str, Any]) -> dict[str, str]:
    """Items that another milestone contract already owns, by owning contract."""

    owned: dict[str, str] = {}
    for path in _string_list(inventory.get("disjoint_from"), "inventory disjoint contracts", allow_empty=True):
        sibling = harness.read_json(harness.ROOT / path)
        gates = sibling.get("gates")
        if not isinstance(gates, list):
            raise harness.HarnessError(f"M7 disjoint contract {path} lacks gates")
        for gate in gates:
            for name in gate.get("items", []) if isinstance(gate, Mapping) else []:
                owned[name] = path
    return owned


def validate_abi_boundary(
    boundary: object, items: set[str], by_name: Mapping[str, Mapping[str, Any]]
) -> None:
    """Cross-check the recorded ABI disposition against the API inventory.

    No selected item may be a crabc libc export, and every selected external
    function must carry the inventory's prefixed test-adapter surface.
    """

    if not isinstance(boundary, Mapping) or set(boundary) != {
        "disposition", "crabc_libc_exported", "external_function_surface", "adapter",
    }:
        raise harness.HarnessError("M7 inventory must record exactly its ABI boundary disposition")
    if boundary["crabc_libc_exported"] is not False or not boundary["disposition"]:
        raise harness.HarnessError("M7 ABI boundary must keep every mi_* item out of libc")
    if not (harness.ROOT / str(boundary["adapter"]) / "Cargo.toml").is_file():
        raise harness.HarnessError("M7 ABI boundary names an absent test adapter")
    exported = sorted(name for name in items if by_name[name].get("crabc_libc_exported") is not False)
    if exported:
        raise harness.HarnessError(f"M7 items would be crabc libc exports: {exported}")
    surface = boundary["external_function_surface"]
    outside = sorted(
        name for name in items
        if by_name[name].get("kind") == "external-function" and by_name[name].get("adapter_surface") != surface
    )
    if outside:
        raise harness.HarnessError(f"M7 external functions outside the {surface} surface: {outside}")


def validate_contract(
    contract: Mapping[str, Any],
    api: Mapping[str, Any],
    pin: Mapping[str, str],
    sibling_items: Mapping[str, str],
) -> dict[str, Any]:
    """Validate inventory closure and evidence honesty without claiming a pass."""

    if contract.get("schema") != SCHEMA or contract.get("format") != 1:
        raise harness.HarnessError("unsupported M7 allocator gate contract")
    upstream = contract.get("upstream")
    if not isinstance(upstream, Mapping) or dict(upstream) != {
        "version": pin["version"], "revision": pin["revision"],
    }:
        raise harness.HarnessError("M7 allocator gate upstream identity mismatch")
    if (api.get("mimalloc_version"), api.get("pinned_revision")) != (pin["version"], pin["revision"]):
        raise harness.HarnessError("M7 inventory authority upstream identity mismatch")
    inventory = contract.get("inventory")
    if not isinstance(inventory, Mapping) or inventory.get("authority") != harness.relative(
        harness.ALLOCATOR_ROOT / "api-v3.5.0.json"
    ):
        raise harness.HarnessError("M7 allocator gate must use the pinned API applicability inventory")
    items, modes = selected_inventory(inventory, api)
    validate_abi_boundary(inventory.get("abi_boundary"), items, _by_name(api.get("items"), "item"))
    shared = sorted(items & set(sibling_items))
    if shared:
        raise harness.HarnessError(
            f"M7 inventory selects items another milestone owns: "
            f"{[f'{name} ({sibling_items[name]})' for name in shared]}"
        )

    evidence = contract.get("evidence")
    if not isinstance(evidence, Mapping) or not evidence:
        raise harness.HarnessError("M7 allocator gate lacks an evidence registry")
    runnable: dict[str, list[str]] = {}
    for evidence_id, record in evidence.items():
        if not isinstance(record, Mapping) or set(record) != {"command", "scope"}:
            raise harness.HarnessError(f"M7 evidence {evidence_id} must record exactly command and scope")
        if not isinstance(record["scope"], str) or not record["scope"]:
            raise harness.HarnessError(f"M7 evidence {evidence_id} lacks a scope")
        command = record["command"]
        if command is None:
            continue
        command = _string_list(command, f"evidence {evidence_id} command")
        if len(command) < 2 or command[0] != "python3" or not (harness.ROOT / command[1]).is_file():
            raise harness.HarnessError(f"M7 evidence {evidence_id} names an absent runner")
        runnable[evidence_id] = command

    gates = contract.get("gates")
    if not isinstance(gates, list) or [
        gate.get("id") if isinstance(gate, Mapping) else None for gate in gates
    ] != list(GATE_IDS):
        raise harness.HarnessError("M7 allocator gate order or identity changed")
    owners = {"item": {}, "mode": {}}
    selections = {"item": items, "mode": modes}
    referenced: set[str] = set()
    blocked: list[str] = []
    for gate in gates:
        gate_id = gate["id"]
        if set(gate) != {"id", "required", "items", "compile_time_modes", "acceptance", "evidence", "blocked_by"}:
            raise harness.HarnessError(f"M7 gate {gate_id} has unexpected fields")
        if gate["required"] is not True:
            raise harness.HarnessError(f"M7 gate {gate_id} must remain required")
        if not isinstance(gate["acceptance"], str) or not gate["acceptance"]:
            raise harness.HarnessError(f"M7 gate {gate_id} lacks an acceptance contract")
        owned = {
            "item": _string_list(gate["items"], f"{gate_id} items", allow_empty=True),
            "mode": _string_list(gate["compile_time_modes"], f"{gate_id} modes", allow_empty=True),
        }
        if gate_id in ITEMLESS_GATE_IDS and (owned["item"] or owned["mode"]):
            raise harness.HarnessError(f"M7 cross-cutting gate {gate_id} owns no items or modes")
        if gate_id not in ITEMLESS_GATE_IDS and not (owned["item"] or owned["mode"]):
            raise harness.HarnessError(f"M7 gate {gate_id} owns neither items nor modes")
        for kind, names in owned.items():
            for name in names:
                if name in owners[kind]:
                    raise harness.HarnessError(
                        f"M7 {kind} {name} is owned by both {owners[kind][name]} and {gate_id}"
                    )
                if name not in selections[kind]:
                    raise harness.HarnessError(f"M7 gate {gate_id} names an unselected {kind}: {name}")
                owners[kind][name] = gate_id
        gate_evidence = _string_list(gate["evidence"], f"{gate_id} evidence")
        unknown = [entry for entry in gate_evidence if entry not in evidence]
        if unknown:
            raise harness.HarnessError(f"M7 gate {gate_id} names undeclared evidence: {unknown}")
        referenced.update(gate_evidence)
        blockers = _string_list(gate["blocked_by"], f"{gate_id} blockers", allow_empty=True)
        if any(entry not in runnable for entry in gate_evidence) and not blockers:
            raise harness.HarnessError(f"M7 gate {gate_id} depends on missing evidence without a blocker")
        if blockers:
            blocked.append(gate_id)
    for kind, selected in selections.items():
        unassigned = sorted(selected - set(owners[kind]))
        if unassigned:
            raise harness.HarnessError(f"M7 gates omit applicable inventory {kind}s: {unassigned}")
    unreferenced = sorted(set(evidence) - referenced)
    if unreferenced:
        raise harness.HarnessError(f"M7 evidence is declared but unused: {unreferenced}")
    return {
        "blocked_gate_ids": blocked,
        "gate_ids": list(GATE_IDS),
        "item_count": len(items),
        "missing_evidence": sorted(set(evidence) - set(runnable)),
        "mode_count": len(modes),
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
            "mode_count": len(gate["compile_time_modes"]),
            "status": status,
        })
    unmet = [record["id"] for record in records if record["status"] != "passed"]
    return {
        "contract": harness.relative(CONTRACT),
        "evidence": {key: dict(value) for key, value in sorted(results.items())},
        "gates": records,
        "item_count": summary["item_count"],
        "mode_count": summary["mode_count"],
        "overall_status": "passed" if not unmet else "unmet",
        "unmet_required": unmet,
    }


def evidence_command(command: Sequence[str], scratch: Path) -> list[str]:
    """Bind the one `{scratch}` placeholder to this run's fresh directory."""

    return [argument.replace(SCRATCH_PLACEHOLDER, str(scratch)) for argument in command]


def run_evidence(runnable: Mapping[str, Sequence[str]], artifacts: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for evidence_id, command in runnable.items():
        name = evidence_id.replace(":", "-")
        # Evidence that refuses to overwrite its own receipt gets a directory
        # that this gate run alone owns.
        scratch = artifacts / name
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True)
        command = evidence_command(command, scratch)
        record = harness.command_record(
            command, cwd=harness.ROOT, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS,
        )
        log = artifacts / f"{name}.log"
        log.write_text(str(record["stdout"]) + str(record["stderr"]))
        results[evidence_id] = {
            "command": list(command),
            "log": harness.relative(log),
            "status": "passed" if record["status"] == 0 else "failed",
        }
    return results


# ---------------------------------------------------------------------------
# differential:options-environment
# ---------------------------------------------------------------------------

def parse_options_trace(
    output: str, description: str, begin: str = OPTIONS_TRACE_BEGIN, end: str = OPTIONS_TRACE_END,
) -> dict[str, str]:
    """Parse one marked `key=value` trace whose values are opaque strings."""

    # libtest prints `test <name> ... ` before the captured stdout, so the
    # begin marker need not start its line; each marker ends one.
    if output.count(begin + "\n") != 1 or output.count(end + "\n") != 1:
        raise harness.HarnessError(f"{description} did not emit exactly one pair of trace markers")
    start = output.index(begin + "\n") + len(begin) + 1
    stop = output.index(end + "\n")
    if stop < start or (stop > 0 and output[stop - 1] != "\n"):
        raise harness.HarnessError(f"{description} emitted misplaced trace markers")
    trace: dict[str, str] = {}
    for line in output[start:stop].splitlines():
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[a-z0-9_.-]+", key):
            raise harness.HarnessError(f"{description} emitted a malformed trace line: {line[:80]}")
        if key in trace:
            raise harness.HarnessError(f"{description} repeated trace key {key}")
        trace[key] = value
    return trace


def require_complete_options_trace(trace: Mapping[str, str], description: str) -> None:
    """Reject a trace that omits a scenario or a descriptor record."""

    count = trace.get("options.count", "")
    if not count.isdigit() or int(count) == 0:
        raise harness.HarnessError(f"{description} lacks its descriptor count")
    names = []
    for index in range(int(count)):
        name = trace.get(f"options.descriptor.{index}", "").partition(",")[0]
        if not name:
            raise harness.HarnessError(f"{description} lacks descriptor {index}")
        names.append(name)
    for scenario in OPTIONS_SCENARIOS:
        for suffix in ("environment", "messages", "lazy_messages"):
            if f"scenario.{scenario}.{suffix}" not in trace:
                raise harness.HarnessError(f"{description} lacks scenario.{scenario}.{suffix}")
        for name in names:
            if not re.fullmatch(r"-?[0-9]+,[012],[0-9]+", trace.get(f"scenario.{scenario}.option.{name}", "")):
                raise harness.HarnessError(f"{description} lacks a valid {scenario} record for {name}")
    for scenario in OPTIONS_ERROR_SCENARIOS:
        for suffix in ("environment", "results", "messages"):
            if f"error.{scenario}.{suffix}" not in trace:
                raise harness.HarnessError(f"{description} lacks error.{scenario}.{suffix}")
    for scenario in OPTIONS_RECURSION_SCENARIOS:
        for suffix in ("environment", "init.messages", "init.verbose", "final_verbose",
                       "direct.messages", "direct.verbose"):
            if f"recursion.{scenario}.{suffix}" not in trace:
                raise harness.HarnessError(f"{description} lacks recursion.{scenario}.{suffix}")
    if not trace.get("api.print"):
        raise harness.HarnessError(f"{description} lacks the options print")


def require_complete_option_effects_trace(trace: Mapping[str, str], description: str) -> None:
    """Reject a trace that omits a decision family."""

    families = {key.partition(".")[0] for key in trace}
    missing = [family for family in OPTION_EFFECT_FAMILIES if family not in families]
    if missing:
        raise harness.HarnessError(f"{description} lacks decision families {missing}")


def require_complete_error_sites_trace(trace: Mapping[str, str], description: str) -> None:
    """Reject a trace that omits a request or one of its three records."""

    for case in ERROR_SITE_CASES:
        for suffix in ("messages", "null", "errno"):
            if f"error_site.{case}.{suffix}" not in trace:
                raise harness.HarnessError(f"{description} lacks error_site.{case}.{suffix}")


def compare_options_traces(c_trace: Mapping[str, str], rust_trace: Mapping[str, str]) -> None:
    missing = sorted(set(c_trace) - set(rust_trace))
    extra = sorted(set(rust_trace) - set(c_trace))
    different = sorted(key for key in set(c_trace) & set(rust_trace) if c_trace[key] != rust_trace[key])
    if missing or extra or different:
        detail = "".join(
            f"\n{key}: C={c_trace[key][:160]} Rust={rust_trace[key][:160]}" for key in different[:8]
        )
        raise harness.HarnessError(
            "C/Rust options trace mismatch: "
            f"missing-in-rust={missing[:8]} extra-in-rust={extra[:8]} different={different[:8]}{detail}"
        )


def c_oracle_trace(
    oracle: Path, subject: str, source: Path, temporary: Path, environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build and run one pinned-C probe against the release configuration."""

    binary = temporary / f"m7-{subject}-c"
    build = harness.command_record(
        [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_LIBC_MUSL=1", "-I", str(source / "include"), "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"],
            str(oracle), "-pthread", "-o", str(binary),
        ],
        cwd=source,
    )
    harness.require_success(build, f"M7 {subject} C build")
    header = harness.command_record((harness.require_tool("readelf"), "-h", str(binary)), cwd=source)
    harness.require_success(header, f"M7 {subject} C ELF identity")
    harness.parse_elf_identity(str(header["stdout"]), "x86_64")
    # An empty environment makes the load-time `_mi_options_init` observe only
    # defaults, which each probe snapshots as its per-scenario reset image.
    execution = harness.command_record((str(binary),), cwd=source, env=dict(environment or {}))
    harness.require_success(execution, f"M7 {subject} C execution")
    return execution


def rust_trace(
    test: str, subject: str, *, integration_test: bool = False, environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run one exact Rust trace test in the launcher's Cargo environment.

    A library trace names one unit test; an integration trace names a
    `native-runtime-test-audit` test target holding exactly one test.
    """

    selection = (
        ["--features", "native-runtime-test-audit", "--test", test, "--"]
        if integration_test else ["--lib", test, "--", "--exact"]
    )
    command = [
        harness.require_tool("cargo"), "test", "--locked", "--target", RUST_TARGET,
        "-p", "crabc-mimalloc", "--no-default-features", *selection, "--nocapture", "--test-threads=1",
    ]
    ambient = {key: value for key, value in os.environ.items() if not key.lower().startswith("mimalloc_")}
    execution = harness.command_record(
        command, cwd=harness.ROOT, env={**ambient, **(environment or {})},
        timeout_seconds=EVIDENCE_TIMEOUT_SECONDS,
    )
    harness.require_success(execution, f"M7 {subject} Rust trace")
    if harness.parse_rust_test_count(str(execution["stdout"]) + "\n" + str(execution["stderr"])) != 1:
        raise harness.HarnessError(f"M7 {subject} Rust trace did not execute exactly one test")
    return execution


def run_trace_differential(
    offline: bool, *, subject: str, oracle: Path, test: str, begin: str, end: str,
    require_complete: Any, report_name: str, integration_test: bool = False,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory(f"crabc-mimalloc-x86_64-m7-{subject}-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        c_execution = c_oracle_trace(oracle, subject, source, temporary, environment)
    rust_execution = rust_trace(test, subject, integration_test=integration_test, environment=environment)
    c_trace = parse_options_trace(str(c_execution["stdout"]), f"pinned C {subject} trace", begin, end)
    rust_trace_image = parse_options_trace(str(rust_execution["stdout"]), f"Rust {subject} trace", begin, end)
    require_complete(c_trace, f"pinned C {subject} trace")
    require_complete(rust_trace_image, f"Rust {subject} trace")
    compare_options_traces(c_trace, rust_trace_image)
    report = {
        "compared_key_count": len(c_trace),
        "c_command": c_execution["command"],
        "rust_command": rust_execution["command"],
        "status": "passed",
        "trace": dict(sorted(c_trace.items())),
    }
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    harness.write_json(ARTIFACTS / report_name, report)
    return report


def run_options_differential(offline: bool) -> dict[str, Any]:
    return run_trace_differential(
        offline, subject="options", oracle=OPTIONS_ORACLE, test=OPTIONS_RUST_TEST,
        begin=OPTIONS_TRACE_BEGIN, end=OPTIONS_TRACE_END,
        require_complete=require_complete_options_trace, report_name="options-environment.json",
    )


def run_error_sites_differential(offline: bool) -> dict[str, Any]:
    return run_trace_differential(
        offline, subject="error-sites", oracle=ERROR_SITES_ORACLE, test=ERROR_SITES_RUST_TEST,
        begin=ERROR_SITES_TRACE_BEGIN, end=ERROR_SITES_TRACE_END,
        require_complete=require_complete_error_sites_trace, report_name="error-sites.json",
        integration_test=True, environment=ERROR_SITES_ENVIRONMENT,
    )


def run_option_effects_differential(offline: bool) -> dict[str, Any]:
    return run_trace_differential(
        offline, subject="option-effects", oracle=OPTION_EFFECTS_ORACLE, test=OPTION_EFFECTS_RUST_TEST,
        begin=OPTION_EFFECTS_TRACE_BEGIN, end=OPTION_EFFECTS_TRACE_END,
        require_complete=require_complete_option_effects_trace, report_name="option-effects.json",
    )


def load_summary() -> tuple[dict[str, Any], dict[str, Any]]:
    contract = harness.read_json(CONTRACT)
    summary = validate_contract(
        contract,
        harness.read_json(harness.ALLOCATOR_ROOT / "api-v3.5.0.json"),
        harness.load_pin(),
        sibling_owned_items(contract.get("inventory", {})),
    )
    return contract, summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
        help="validate the contract and inventory closure without executing evidence")
    mode.add_argument("--gate", choices=GATE_IDS, help="execute only this gate's runnable evidence")
    mode.add_argument("--options-differential", action="store_true",
        help="run the pinned-C/Rust options/environment differential")
    mode.add_argument("--option-effects-differential", action="store_true",
        help="run the pinned-C/Rust option-effects differential")
    mode.add_argument("--error-sites-differential", action="store_true",
        help="run the pinned-C/Rust `_mi_error_message` site differential")
    parser.add_argument("--offline", action="store_true", help="require the verified archive in the local cache")
    arguments = parser.parse_args(argv)
    if arguments.options_differential:
        report = run_options_differential(arguments.offline)
        print(f"M7 options/environment differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.error_sites_differential:
        report = run_error_sites_differential(arguments.offline)
        print(f"M7 error-site differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.option_effects_differential:
        report = run_option_effects_differential(arguments.offline)
        print(f"M7 option-effects differential passed: {report['compared_key_count']} keys")
        return 0
    contract, summary = load_summary()
    if arguments.check:
        print(
            f"M7 gate contract valid: {summary['item_count']} interface items and "
            f"{summary['mode_count']} compile-time modes in {len(summary['gate_ids'])} gates; "
            f"{len(summary['blocked_gate_ids'])} gates blocked; "
            f"{len(summary['missing_evidence'])} evidence entries missing"
        )
        return 0
    harness.require_native_x86_64()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    runnable = summary["runnable_evidence"]
    if arguments.gate is not None:
        selected = next(gate for gate in contract["gates"] if gate["id"] == arguments.gate)
        runnable = {key: value for key, value in runnable.items() if key in selected["evidence"]}
        contract = {**contract, "gates": [selected]}
    report = gate_report(contract, summary, run_evidence(runnable, ARTIFACTS))
    report_path = ARTIFACTS / ("report.json" if arguments.gate is None else f"{arguments.gate}.json")
    harness.write_json(report_path, report)
    for record in report["gates"]:
        print(f"{record['id']}: {record['status']}")
        for evidence_id, status in record["evidence"].items():
            print(f"  {evidence_id}: {status}")
    if report["overall_status"] != "passed":
        print(
            f"M7 unmet: {len(report['unmet_required'])}/{len(report['gates'])} required gates; "
            f"report {harness.relative(report_path)}",
            file=sys.stderr,
        )
        return 1
    print("M7 passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
