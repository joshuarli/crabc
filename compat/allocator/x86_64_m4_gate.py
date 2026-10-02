#!/usr/bin/env python3
"""Fail-closed native Linux/x86-64 allocation-operation evidence.

The selected interfaces cover calloc, realloc, alignment, usable size,
medium/large/singleton allocations, collection, OOM preservation, the C
adapter, and applicable upstream operation tests. The pinned applicability
inventory partitions these interfaces into gates with executable evidence.
An applicable item handled by another interface group is listed in
`excluded_items` with that owner and reason, never silently dropped.

A gate passes only when it carries no reviewed blocker and every evidence
entry has a command that executed successfully on this run. Evidence without a
command is declared missing, and a gate that depends on it must name a
blocker, so the contract cannot claim completion that no executable check
supports. Runnable evidence is always executed; its pass never removes a
blocker by itself.

The evidence checks this module owns:

- `--native-tests` runs the focused native-engine integration regressions,
  each its own test process;
- `--differential SCENARIO` links the shared C driver
  `x86_64_m4_operations_driver.c` once against the pinned C sources and once
  against the native `mi_*` adapter (`native-mi-adapter/`), runs the scenario
  in a fresh process of each, and requires identical address-free traces; the
  `operations` scenario also requires identical termination for every
  process-terminating `mi_new` case;
- `--differential SCENARIO --build-profile debug --valid-clients-only`
  retains an opt0 legal-client diagnostic with source-built abort-only core;
  `--source-profile` independently selects the pinned source macros. Its
  products and reports remain separate from full gate qualification;
- `--adapter-boundary` audits the native adapter static library: its defined
  `mi_*` globals include every selected external function and only functions
  the pinned header declares. Heap, reservation, option and statistics checks
  use the same adapter. It defines no libc allocator entry or C mimalloc `_mi_*` internal, and a C probe that
  takes every function's address through the pinned `mimalloc.h` links
  against it alone and runs.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import tempfile
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import run as harness
import perf_engine_x86_64 as engine
import perf_integrated_x86_64 as integrated


CONTRACT = harness.ALLOCATOR_ROOT / "m4-gate-x86_64-v3.5.0.json"
SCHEMA = "crabc-mimalloc-x86_64-m4-gate"
GATE_IDS = (
    "m4.allocation",
    "m4.free",
    "m4.realloc",
    "m4.aligned",
    "m4.usable-size",
    "m4.source-conveniences",
    "m4.collection",
    "m4.page-kinds",
    "m4.oom-failure",
    "m4.c-adapter",
    "m4.upstream",
)
# Cross-cutting gates own behavior rather than interface items.
ITEMLESS_GATE_IDS = frozenset({"m4.page-kinds", "m4.oom-failure", "m4.c-adapter", "m4.upstream"})
EVIDENCE_TIMEOUT_SECONDS = 3600
# An evidence command argument may name this run's fresh per-evidence
# directory, for runners that refuse to replace an existing receipt.
SCRATCH_PLACEHOLDER = "{scratch}"
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m4-gate"
RUST_TARGET = "x86_64-unknown-linux-musl"

# `unit:native-operations`: integration-test targets of `crabc-mimalloc`.
# Each target is a separate process, so every one starts its own native
# runtime. The audit feature is the one those targets' manifests require.
NATIVE_TESTS = (
    "native_aligned_reallocate",
    "native_concurrent_nonlocal_reallocate",
    "native_huge_singleton_local_free",
    "native_pointer_current_owner_reallocate",
    "native_pointer_first_nonlocal_reallocate",
)
NATIVE_TEST_FEATURES = "native-runtime-test-audit"

OPERATIONS_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m4_operations_driver.c"
OOM_SURVIVAL_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m4_oom_survival_driver.c"
OPERATIONS_TRACE_BEGIN = "CRABC_MI_M4_OPERATIONS_TRACE_BEGIN"
OPERATIONS_TRACE_END = "CRABC_MI_M4_OPERATIONS_TRACE_END"
# Driver scenarios, each one evidence entry run in fresh processes.
DIFFERENTIAL_SCENARIOS = ("operations", "page-kinds", "collection", "oom", "oom-survival", "threads", "aligned-preservation")
# Scenarios the driver ends with `abort()` in pinned C (plain-C `mi_new`
# without a new handler); both processes must terminate the same way.
ABORT_SCENARIOS = (
    "new_n_overflow", "new_too_large", "new_aligned_too_large",
    "new_realloc_too_large", "new_reallocn_overflow",
)
# Defining any of these would make the adapter an allocator interposer.
C_ALLOCATOR_NAMES = frozenset({
    "malloc", "calloc", "realloc", "free", "cfree", "aligned_alloc", "posix_memalign", "memalign",
    "valloc", "pvalloc", "reallocarray", "reallocarr", "malloc_usable_size", "malloc_size",
    "__libc_malloc", "__libc_calloc", "__libc_realloc", "__libc_free", "__libc_memalign",
})
ADAPTER_PACKAGE = "crabc-mimalloc-native-mi-adapter"
ADAPTER_STATICLIB = "libcrabc_mimalloc_native_mi_adapter.a"


def _string_list(value: object, subject: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or not all(isinstance(entry, str) and entry for entry in value)
        or len(set(value)) != len(value)
    ):
        raise harness.HarnessError(f"M4 gate {subject} must be a list of unique non-empty strings")
    return list(value)


def selected_inventory(inventory: Mapping[str, Any], api: Mapping[str, Any]) -> set[str]:
    """Return every applicable interface item the contract's selection rule names."""

    items = api.get("items")
    if not isinstance(items, list):
        raise harness.HarnessError("M4 inventory authority lacks an item list")
    by_name: dict[str, Mapping[str, Any]] = {}
    for item in items:
        if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
            raise harness.HarnessError("M4 inventory authority has a malformed item")
        if item["name"] in by_name:
            raise harness.HarnessError(f"M4 inventory authority repeats {item['name']}")
        by_name[item["name"]] = item
    groups = set(_string_list(inventory.get("groups"), "inventory groups"))
    unknown = sorted(groups - {item.get("group") for item in by_name.values()})
    if unknown:
        raise harness.HarnessError(f"M4 inventory names unknown groups: {unknown}")
    selected = {
        name for name, item in by_name.items()
        if item.get("target_applicability") == "applicable" and item.get("group") in groups
    }
    for name in _string_list(inventory.get("additional_items"), "inventory additional items", allow_empty=True):
        item = by_name.get(name)
        if item is None:
            raise harness.HarnessError(f"M4 additional inventory item is absent: {name}")
        if item.get("target_applicability") != "applicable":
            raise harness.HarnessError(f"M4 additional inventory item is not applicable: {name}")
        if name in selected:
            raise harness.HarnessError(f"M4 additional inventory item is already selected: {name}")
        selected.add(name)
    return selected


def sibling_owned_items(inventory: Mapping[str, Any]) -> dict[str, str]:
    """Map interfaces handled by a separate group to their owning contract."""

    owned: dict[str, str] = {}
    for path in _string_list(inventory.get("disjoint_from"), "inventory disjoint contracts", allow_empty=True):
        sibling = harness.read_json(harness.ROOT / path)
        gates = sibling.get("gates")
        if not isinstance(gates, list):
            raise harness.HarnessError(f"M4 disjoint contract {path} lacks gates")
        for gate in gates:
            for name in gate.get("items", []) if isinstance(gate, Mapping) else []:
                owned[name] = path
    return owned


def validate_contract(
    contract: Mapping[str, Any],
    api: Mapping[str, Any],
    pin: Mapping[str, str],
    sibling_items: Mapping[str, str],
) -> dict[str, Any]:
    """Validate inventory closure and evidence honesty without claiming a pass."""

    if contract.get("schema") != SCHEMA or contract.get("format") != 1:
        raise harness.HarnessError("unsupported M4 allocator gate contract")
    upstream = contract.get("upstream")
    if not isinstance(upstream, Mapping) or dict(upstream) != {
        "version": pin["version"], "revision": pin["revision"],
    }:
        raise harness.HarnessError("M4 allocator gate upstream identity mismatch")
    if (api.get("mimalloc_version"), api.get("pinned_revision")) != (pin["version"], pin["revision"]):
        raise harness.HarnessError("M4 inventory authority upstream identity mismatch")
    inventory = contract.get("inventory")
    if not isinstance(inventory, Mapping) or inventory.get("authority") != harness.relative(
        harness.ALLOCATOR_ROOT / "api-v3.5.0.json"
    ):
        raise harness.HarnessError("M4 allocator gate must use the pinned API applicability inventory")
    selected = selected_inventory(inventory, api)
    # Sibling operations have separate owners; every excluded operation must
    # carry a nonempty reason in this component's inventory.
    selected -= set(sibling_items)
    excluded = inventory.get("excluded_items")
    if not isinstance(excluded, Mapping) or not all(
        isinstance(reason, str) and reason for reason in excluded.values()
    ):
        raise harness.HarnessError("M4 excluded items must map each name to its owner and reason")
    stray = sorted(set(excluded) - selected)
    if stray:
        raise harness.HarnessError(f"M4 excludes items its selection does not reach: {stray}")
    items = selected - set(excluded)

    evidence = contract.get("evidence")
    if not isinstance(evidence, Mapping) or not evidence:
        raise harness.HarnessError("M4 allocator gate lacks an evidence registry")
    runnable: dict[str, list[str]] = {}
    for evidence_id, record in evidence.items():
        if not isinstance(record, Mapping) or set(record) != {"command", "scope"}:
            raise harness.HarnessError(f"M4 evidence {evidence_id} must record exactly command and scope")
        if not isinstance(record["scope"], str) or not record["scope"]:
            raise harness.HarnessError(f"M4 evidence {evidence_id} lacks a scope")
        command = record["command"]
        if command is None:
            continue
        command = _string_list(command, f"evidence {evidence_id} command")
        if len(command) < 2 or command[0] != "python3" or not (harness.ROOT / command[1]).is_file():
            raise harness.HarnessError(f"M4 evidence {evidence_id} names an absent runner")
        runnable[evidence_id] = command

    gates = contract.get("gates")
    if not isinstance(gates, list) or [
        gate.get("id") if isinstance(gate, Mapping) else None for gate in gates
    ] != list(GATE_IDS):
        raise harness.HarnessError("M4 allocator gate order or identity changed")
    owners: dict[str, str] = {}
    referenced: set[str] = set()
    blocked: list[str] = []
    for gate in gates:
        gate_id = gate["id"]
        if set(gate) != {"id", "required", "items", "acceptance", "evidence", "blocked_by"}:
            raise harness.HarnessError(f"M4 gate {gate_id} has unexpected fields")
        if gate["required"] is not True:
            raise harness.HarnessError(f"M4 gate {gate_id} must remain required")
        if not isinstance(gate["acceptance"], str) or not gate["acceptance"]:
            raise harness.HarnessError(f"M4 gate {gate_id} lacks an acceptance contract")
        names = _string_list(gate["items"], f"{gate_id} items", allow_empty=gate_id in ITEMLESS_GATE_IDS)
        if gate_id in ITEMLESS_GATE_IDS and names:
            raise harness.HarnessError(f"M4 cross-cutting gate {gate_id} owns no interface items")
        for name in names:
            if name in owners:
                raise harness.HarnessError(f"M4 item {name} is owned by both {owners[name]} and {gate_id}")
            if name not in items:
                raise harness.HarnessError(f"M4 gate {gate_id} names an unselected item: {name}")
            owners[name] = gate_id
        gate_evidence = _string_list(gate["evidence"], f"{gate_id} evidence")
        unknown = [entry for entry in gate_evidence if entry not in evidence]
        if unknown:
            raise harness.HarnessError(f"M4 gate {gate_id} names undeclared evidence: {unknown}")
        referenced.update(gate_evidence)
        blockers = _string_list(gate["blocked_by"], f"{gate_id} blockers", allow_empty=True)
        if any(entry not in runnable for entry in gate_evidence) and not blockers:
            raise harness.HarnessError(f"M4 gate {gate_id} depends on missing evidence without a blocker")
        if blockers:
            blocked.append(gate_id)
    unassigned = sorted(items - set(owners))
    if unassigned:
        raise harness.HarnessError(f"M4 gates omit applicable inventory items: {unassigned}")
    unreferenced = sorted(set(evidence) - referenced)
    if unreferenced:
        raise harness.HarnessError(f"M4 evidence is declared but unused: {unreferenced}")
    return {
        "blocked_gate_ids": blocked,
        "excluded_items": dict(sorted(excluded.items())),
        "gate_ids": list(GATE_IDS),
        "item_count": len(items),
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
        "excluded_items": dict(summary["excluded_items"]),
        "gates": records,
        "item_count": summary["item_count"],
        "overall_status": "passed" if not unmet else "unmet",
        "unmet_required": unmet,
    }


def report_provenance(report: Mapping[str, Any]) -> dict[str, Any]:
    """Bind executed evidence to the checkout and its retained raw logs."""

    return {
        "git": engine.git_provenance(),
        "seal": {**integrated.source_seal(), "gate": engine.file_record(Path(__file__)),
                 "contract": engine.file_record(CONTRACT)},
        "evidence": {name: engine.file_record(harness.ROOT / record["log"])
                     for name, record in report["evidence"].items()},
    }


def evidence_command(command: Sequence[str], scratch: Path) -> list[str]:
    """Bind the one `{scratch}` placeholder to this run's fresh directory."""

    return [argument.replace(SCRATCH_PLACEHOLDER, str(scratch)) for argument in command]


def run_evidence(runnable: Mapping[str, Sequence[str]], artifacts: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for evidence_id, command in runnable.items():
        name = evidence_id.replace(":", "-")
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
# unit:native-operations
# ---------------------------------------------------------------------------

def run_native_tests() -> dict[str, Any]:
    """Run each focused native-engine integration target as its own process."""

    harness.require_native_x86_64()
    command = [
        harness.require_tool("cargo"), "test", "--locked", "--target", RUST_TARGET,
        "-p", "crabc-mimalloc", "--no-default-features", "--features", NATIVE_TEST_FEATURES, "--no-fail-fast",
        *(argument for name in NATIVE_TESTS for argument in ("--test", name)),
    ]
    execution = harness.command_record(
        command, cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=EVIDENCE_TIMEOUT_SECONDS,
    )
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    harness.write_json(ARTIFACTS / "native-operations-execution.json", execution)
    harness.require_success(execution, "M4 native-engine regressions")
    output = str(execution["stdout"]) + "\n" + str(execution["stderr"])
    # Every target reports its own libtest summary; a target that ran no test
    # is a selection defect, not a pass.
    summaries = [line for line in output.splitlines() if line.startswith("test result: ok.")]
    if len(summaries) != len(NATIVE_TESTS) or any(" 0 passed" in line for line in summaries):
        raise harness.HarnessError("M4 native-engine regressions did not run one nonempty suite per target")
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, True)
    with harness.temporary_directory("crabc-mimalloc-x86_64-m4-canary-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        c_driver = build_c_driver(source, temporary, profile="debug-1")
        c_execution = run_driver(c_driver, ("padding-canary",))
        harness.require_success(c_execution, "M4 pinned two-key padding canary")
        rust_execution = harness.command_record([
            harness.require_tool("cargo"), "test", "--locked", "--target", RUST_TARGET,
            "-p", "crabc-mimalloc", "--lib", "--no-default-features",
            "alloc::tests::debug_padding_canary_uses_independent_page_keys", "--", "--exact", "--quiet", "--nocapture",
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
        harness.require_success(rust_execution, "M4 native two-key padding canary")
        c_canaries = parse_operations_trace(str(c_execution["stdout"]), "pinned padding canaries")
        rust_canaries = dict(line.split("=", 1) for line in str(rust_execution["stdout"]).splitlines()
                             if line.startswith("padding.canary."))
        compare_operations_traces(c_canaries, rust_canaries)
    report = {"command": execution["command"], "status": "passed", "targets": list(NATIVE_TESTS)}
    report["padding_canaries"] = c_canaries
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    harness.write_json(ARTIFACTS / "native-operations.json", report)
    return report


# ---------------------------------------------------------------------------
# differential:operations
# ---------------------------------------------------------------------------

def parse_operations_trace(output: str, description: str) -> dict[str, str]:
    """Parse one marked, ordered `key=value` trace with unique keys."""

    lines = output.splitlines()
    if lines.count(OPERATIONS_TRACE_BEGIN) != 1 or lines.count(OPERATIONS_TRACE_END) != 1:
        raise harness.HarnessError(f"{description} did not emit exactly one complete trace")
    start = lines.index(OPERATIONS_TRACE_BEGIN) + 1
    stop = lines.index(OPERATIONS_TRACE_END)
    trace: dict[str, str] = {}
    for line in lines[start:stop]:
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z0-9_.]+", key):
            raise harness.HarnessError(f"{description} emitted a malformed trace line: {line[:80]}")
        if key in trace:
            raise harness.HarnessError(f"{description} repeated trace key {key}")
        trace[key] = value
    if not trace:
        raise harness.HarnessError(f"{description} emitted an empty trace")
    return trace


def compare_operations_traces(c_trace: Mapping[str, str], rust_trace: Mapping[str, str], *,
                              private_source_profile: str | None = None) -> None:
    """Require equal traces, reporting differences in C trace order.

    Allocation ids and reuse relations cascade, so the first differing key
    is the one that locates a divergence.
    """

    # Secure allocation randomizes block selection. For the ordinary class
    # allocation matrix, only alignment beyond the word/block guarantee is
    # incidental. Keep all other observations exact, including usable size,
    # reuse and page placement, until their operation-specific bounds are known.
    if private_source_profile in {f"secure-{level}" for level in range(1, 6)}:
        def bounded_alignment(trace: Mapping[str, str]) -> dict[str, str]:
            result = dict(trace)
            for key, value in trace.items():
                request = re.fullmatch(r"(?:malloc|zalloc|calloc)\.\d+\.(\d+)", key)
                allocation = re.fullmatch(
                    r"(id:\d+,reuse:(?:-|\d+),usable:\d+,align:)(\d+)(,slice:\d+)", value)
                if request is None or allocation is None:
                    continue
                minimum = 3 if int(request[1]) <= 8 else 4
                if not minimum <= int(allocation[2]) <= 16:
                    raise harness.HarnessError(f"private secure allocation {key} violates malloc alignment: {value}")
                result[key] = f"{allocation[1]}{minimum}{allocation[3]}"
            return result
        c_trace = bounded_alignment(c_trace)
        rust_trace = bounded_alignment(rust_trace)
    if list(c_trace) == list(rust_trace) and dict(c_trace) == dict(rust_trace):
        return
    missing = [key for key in c_trace if key not in rust_trace]
    extra = [key for key in rust_trace if key not in c_trace]
    different = [key for key in c_trace if key in rust_trace and c_trace[key] != rust_trace[key]]
    detail = "".join(f"\n{key}: C={c_trace[key]} Rust={rust_trace[key]}" for key in different[:12])
    raise harness.HarnessError(
        f"C/Rust operations trace mismatch: {len(different)} differing, {len(missing)} missing, "
        f"{len(extra)} extra; first missing {missing[:4]}, first extra {extra[:4]}{detail}"
    )


def compare_assertion_control(profile: str, case: str, c_record: Mapping[str, object],
                              native_record: Mapping[str, object]) -> None:
    """Distinguish source assertion preconditions from valid allocation observations.

    A debug source assertion must abort at the selected precondition. The
    native implementation still has to return the documented error and leave
    a refused replacement's live payload intact.
    """
    controls = {
        "reallocarr-null": ("null,1,1", "22,22", "ptrp != NULL", "mi_reallocarr"),
        "reallocarr-zero-size": ("63,1,0", "22,22,1", "size != 0", "mi_reallocarr"),
        "aligned-invalid": ("100,64;200,24", "1,22,1",
                            "mi_alignment_is_valid(alignment)", "mi_theap_realloc_zero_aligned_at"),
        "aligned-at-invalid": ("73,64,7;150,3,7", "1,22,1",
                               "mi_alignment_is_valid(alignment)", "mi_theap_realloc_zero_aligned_at"),
    }
    if profile not in (*API_PROFILES, "secure-1", "secure-2") or case not in controls:
        raise harness.HarnessError("unknown assertion control profile or case")
    arguments, outcome, assertion, function = controls[case]
    expected = {"control.input": arguments, "control.outcome": outcome}
    if native_record.get("status") != 0:
        raise harness.HarnessError(f"{case} native control did not return normally")
    native_trace = parse_operations_trace(str(native_record.get("stdout", "")), f"{case} native control")
    if native_trace != expected:
        raise harness.HarnessError(f"{case} native control input or outcome differs: {native_trace}")
    if profile == "debug-1":
        partial = f"{OPERATIONS_TRACE_BEGIN}\ncontrol.input={arguments}\n"
        diagnostic = str(c_record.get("stderr", ""))
        if (c_record.get("status") != -6 or c_record.get("stdout") != partial
                or f'assertion: "{assertion}"' not in diagnostic or function not in diagnostic):
            raise harness.HarnessError(f"{case} source control did not abort at its exact assertion")
    else:
        if c_record.get("status") != 0:
            raise harness.HarnessError(f"{case} source control did not return normally")
        c_trace = parse_operations_trace(str(c_record.get("stdout", "")), f"{case} source control")
        if c_trace != expected:
            raise harness.HarnessError(f"{case} source control input or outcome differs: {c_trace}")


def compare_source_client_control(profile: str, case: str, original: Mapping[str, Mapping[str, Any]],
                                  oracle: Mapping[str, Mapping[str, Any]]) -> None:
    """Keep the source debug rejection separate from valid-client equality.

    The positive source oracle and both native invocations must agree on every
    observation. Only the exact original source word-alignment rejection is
    accepted as a negative control; payload loss or another diagnostic fails.
    """
    if profile not in (*API_PROFILES, "secure-1", "secure-2") or case not in SOURCE_CLIENT_CONTROLS:
        raise harness.HarnessError("unknown source live-client control")
    positive = {}
    for side in ("c", "rust"):
        record = oracle[side]
        harness.require_success(record, f"{case} {side} positive live-client control")
        validate_valid_domain_option(profile, side, record)
        positive[side] = parse_operations_trace(str(record["stdout"]), f"{case} {side} positive control")
    compare_operations_traces(positive["c"], positive["rust"])
    harness.require_success(original["rust"], f"{case} original native live-client control")
    compare_operations_traces(positive["c"], parse_operations_trace(
        str(original["rust"]["stdout"]), f"{case} original native control"))
    if case == "interior-api-modes":
        expected = {}
        for heap in (0, 1):
            urealloc = positive["c"].get(f"api_modes.urealloc_interior.{heap}.0", "").split(",")
            if (len(urealloc) != 5 or urealloc[0] != "0" or urealloc[3:] != ["0", "1"]
                    or not urealloc[1].isdigit() or not urealloc[2].isdigit()
                    or int(urealloc[1]) < 64 or int(urealloc[2]) < 129):
                raise harness.HarnessError("live-client urealloc did not preserve its payload and extents")
            for operation in ("heap_ordinary", "heap_aligned_zero"):
                if positive["c"].get(f"api_modes.{operation}_interior.{heap}.0") != "0,0,1":
                    raise harness.HarnessError("live-client Heap replacement did not preserve valid behavior")
            expected[f"api_modes.urealloc_interior.{heap}.0"] = "1,0,0,1,1"
            expected[f"api_modes.heap_ordinary_interior.{heap}.0"] = "1,1,1"
            expected[f"api_modes.heap_aligned_zero_interior.{heap}.0"] = "1,1,1"
        diagnostics = ["mi_realloc", "mi_realloc", "mi_usable_size"] * 2
    else:
        size, alignment, offset = (73, 64, 7) if case == "usable-free-73" else (1000, 4096, 13)
        extent = positive["c"].get("control.usable", "").split(",")
        if (len(extent) != 3 or not extent[0].isdigit() or int(extent[0]) < size
                or extent[1:] != ["0", "0"] or positive["c"].get("control.client") != "1,1"
                or positive["c"].get("control.input") != f"{size},{alignment},{offset}"
                or positive["c"].get("control.free") != "0,0"):
            raise harness.HarnessError("live-client usable/free control lost its valid extent or payload")
        expected = {"control.input": f"{size},{alignment},{offset}", "control.client": "1,1",
                    "control.usable": "0,0,1", "control.free": "0,2"}
        diagnostics = ["mi_usable_size", "mi_free"]
    if list(positive["c"]) != list(expected):
        raise harness.HarnessError("positive live-client control observation roster changed")
    source = original["c"]
    trace = parse_operations_trace(str(source["stdout"]), f"{case} original source control")
    if profile != "debug-1":
        harness.require_success(source, f"{case} original source live-client control")
        compare_operations_traces(positive["c"], trace)
        return
    errors = re.findall(r"(mi_[a-z_]+): invalid \(unaligned\) pointer: 0x[0-9a-fA-F]+", str(source["stderr"]))
    if (source.get("status") != 1 or list(trace) != list(expected) or trace != expected or errors != diagnostics
            or str(source["stderr"]).count("mimalloc: error:") != len(diagnostics)):
        raise harness.HarnessError("original source live-client control differs from its exact debug rejection")


GUARDED_API_PROFILE_BASES = {
    "guarded": "release",
    "guarded-debug-1": "debug-1",
    "guarded-secure-3": "secure-3",
    "guarded-stat-2": "stat-2",
    "guarded-debug-2": "debug-2",
    "guarded-debug-3": "debug-3",
    "guarded-stat-1": "stat-1",
    "guarded-secure-1": "secure-1",
    "guarded-secure-2": "secure-2",
    "guarded-secure-4": "secure-4",
    "guarded-secure-5": "secure-5",
}


def api_profile_flags(profile: str) -> tuple[str, ...]:
    if profile in GUARDED_API_PROFILE_BASES:
        ordinary = api_profile_flags(GUARDED_API_PROFILE_BASES[profile])
        return (*(flag for flag in ordinary if not flag.startswith("-DMI_GUARDED=")),
                "-DMI_GUARDED=1")
    flags = tuple(flag for flag in harness.CONFIGURATION_PROFILES["release"]
                  if not flag.startswith(("-DMI_DEBUG=", "-DMI_STAT="))
                  and not (profile.startswith("secure-") and flag.startswith("-DMI_SECURE=")))
    return (*flags, *{
        "release": ("-DMI_DEBUG=0", "-DMI_STAT=0"),
        "secure-1": ("-DMI_DEBUG=0", "-DMI_STAT=0", "-DMI_SECURE=1"),
        "secure-2": ("-DMI_DEBUG=0", "-DMI_STAT=0", "-DMI_SECURE=2"),
        "secure-3": ("-DMI_DEBUG=0", "-DMI_STAT=0", "-DMI_SECURE=3"),
        "secure-4": ("-DMI_DEBUG=0", "-DMI_STAT=0", "-DMI_SECURE=4"),
        "secure-5": ("-DMI_DEBUG=0", "-DMI_STAT=0", "-DMI_SECURE=5"),
        "stat-1": ("-DMI_DEBUG=0", "-DMI_STAT=1"),
        "stat-2": ("-DMI_DEBUG=0", "-DMI_STAT=2"),
        "debug-1": ("-DMI_DEBUG=1", "-DMI_STAT=2", "-DMI_PADDING=1"),
        "debug-2": ("-DMI_DEBUG=2", "-DMI_STAT=2", "-DMI_PADDING=1"),
        "debug-3": ("-DMI_DEBUG=3", "-DMI_STAT=2", "-DMI_PADDING=1"),
    }[profile])


def api_profile_features(profile: str) -> tuple[str, ...]:
    """Select actual crate features independently of the source C macro names."""
    ordinary = GUARDED_API_PROFILE_BASES.get(profile, profile)
    api_profile_flags(ordinary)
    features = () if ordinary == "release" else (f"mi-{ordinary}",)
    return ("mi-guarded", *features) if profile in GUARDED_API_PROFILE_BASES else features


def build_c_driver(source: Path, temporary: Path, driver_source: Path = OPERATIONS_DRIVER,
                   profile: str = "release", *, build_profile: str = "release") -> Path:
    """Link the shared driver against the pinned `src/static.c` source."""

    compiler = harness.require_tool("musl-gcc")
    if build_profile not in {"release", "debug"}:
        raise harness.HarnessError("unknown operation build profile")
    flags = api_profile_flags(profile)
    if build_profile == "debug":
        flags = (*(flag for flag in flags if not flag.startswith("-O")), "-O0")
    driver = temporary / "operations-c"
    build = harness.command_record(
        [
            compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
            "-DCRABC_MI_M4_SOURCE_CANARY=1",
            *flags, "-I", str(source / "include"),
            str(driver_source), str(source / "src/static.c"), "-pthread", "-o", str(driver),
        ],
        cwd=source,
    )
    harness.write_json(temporary / "c-build.json", build)
    harness.require_success(build, "M4 operations C driver build")
    return driver


def debug_adapter_environment(temporary: Path) -> tuple[list[str], dict[str, str], dict[str, Any]]:
    """Compile the no-alloc adapter with the pinned abort-only core sources.

    Stock core carries personality references even for an aborting consumer.
    Rebuilding core removes that unused unwind boundary rather than supplying
    a dummy personality or borrowing a foreign compiler runtime.
    """

    path = harness.ROOT / "compat/x86_64/native_static_source_runtime_closure.py"
    spec = importlib.util.spec_from_file_location("m4_source_runtime", path)
    assert spec is not None and spec.loader is not None
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    frontend, environment = runtime.pinned_environment()
    discover = harness.command_record(
        [frontend["argv0"], "run", runtime.TOOLCHAIN, "rustc", "--print", "sysroot"],
        cwd=harness.ROOT, env=environment,
    )
    harness.require_success(discover, "debug adapter pinned sysroot discovery")
    source = Path(str(discover["stdout"]).strip()) / "lib/rustlib/src/rust/library"
    vendor = runtime.private_vendor(
        temporary, source,
        harness.ROOT / ".work/x86_64/cargo/native-static-source-runtime-vendor",
    )
    flags = runtime.runtime_flags("pic")
    environment.update({
        "CARGO_HOME": str(temporary / "cargo-home"),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_INCREMENTAL": "0",
        "CARGO_PROFILE_DEV_OPT_LEVEL": "0",
        "CARGO_PROFILE_TEST_OPT_LEVEL": "0",
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags),
    })
    provenance = {
        "frontend": frontend,
        "vendor": vendor,
        "flags": list(flags),
        "environment": environment,
        "core_source": runtime.file_record(source / "core/src/lib.rs", "pinned core source"),
        "compiler_builtins_source": runtime.file_record(
            source / runtime.RUNTIME_SOURCES["compiler_builtins"], "pinned compiler helper source"),
    }
    return [frontend["argv0"], "run", runtime.TOOLCHAIN, "cargo",
            "-Zbuild-std=core,compiler_builtins"], environment, provenance


def build_adapter_library(temporary: Path, profile: str = "release", *, build_profile: str = "release") -> Path:
    """Build the native adapter static library in this run's own target."""

    target_dir = temporary / "cargo-target"
    features = api_profile_features(profile)
    if build_profile not in {"release", "debug"}:
        raise harness.HarnessError("unknown operation build profile")
    environment = dict(os.environ)
    frontend = [harness.require_tool("cargo")]
    if build_profile == "debug":
        frontend, environment, provenance = debug_adapter_environment(temporary)
        harness.write_json(temporary / "adapter-source-runtime.json", provenance)
    build = harness.command_record(
        [
            *frontend, "build", "--locked", *(('--release',) if build_profile == "release" else ('--offline',)), "--message-format=json", "--target", RUST_TARGET,
            "-p", ADAPTER_PACKAGE, "--target-dir", str(target_dir),
            *(("--features", ",".join(f"crabc-mimalloc/{feature}" for feature in features)) if features else ()),
        ],
        cwd=harness.ROOT, env=environment, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS,
    )
    harness.write_json(temporary / "adapter-build.json", build)
    harness.require_success(build, "M4 native adapter build")
    library = target_dir / RUST_TARGET / build_profile / ADAPTER_STATICLIB
    build["artifact"] = harness.artifact_record(library)
    harness.write_json(temporary / "adapter-build.json", build)
    return library


def build_rust_driver(source: Path, temporary: Path, driver_source: Path = OPERATIONS_DRIVER,
                      profile: str = "release", *, build_profile: str = "release") -> Path:
    """Link the same driver, unchanged, against the native adapter only."""

    library = build_adapter_library(temporary, profile, build_profile=build_profile)
    driver = temporary / "operations-rust"
    link = harness.command_record(
        [
            harness.require_tool("musl-gcc"), "-std=c11", "-O0" if build_profile == "debug" else "-O2", "-I", str(source / "include"),
            str(driver_source), str(library), "-pthread", "-o", str(driver),
        ],
        cwd=source,
    )
    harness.write_json(temporary / "rust-link.json", link)
    harness.require_success(link, "M4 operations Rust driver link")
    return driver


def run_driver(driver: Path, arguments: Sequence[str] = ()) -> dict[str, Any]:
    return harness.command_record((str(driver), *arguments), cwd=driver.parent, env={}, timeout_seconds=600)


def run_operations_differential(offline: bool, scenario: str, *, build_profile: str = "release",
                                source_profile: str = "release", valid_clients_only: bool = False) -> dict[str, Any]:
    if build_profile not in {"release", "debug"} or (build_profile == "debug" and not valid_clients_only):
        raise harness.HarnessError("debug operation builds require the explicit valid-client domain")
    if source_profile != "release" and not valid_clients_only:
        raise harness.HarnessError("nondefault source modes require the private valid-client domain")
    api_profile_flags(source_profile)
    harness.require_native_x86_64()
    artifacts = ARTIFACTS
    if valid_clients_only:
        artifacts = artifacts / "private-valid-clients" / build_profile / source_profile
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / f"{scenario}.json").unlink(missing_ok=True)
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    context = (contextlib.nullcontext(tempfile.mkdtemp(prefix=f"{scenario}-", dir=artifacts)) if valid_clients_only
               else harness.temporary_directory("crabc-mimalloc-x86_64-m4-operations-"))
    with context as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        driver_source = OOM_SURVIVAL_DRIVER if scenario == "oom-survival" else OPERATIONS_DRIVER
        build_arguments = ({"profile": source_profile, "build_profile": build_profile}
                           if valid_clients_only or source_profile != "release" else {})
        drivers = {"c": build_c_driver(source, temporary, driver_source, **build_arguments),
                   "rust": build_rust_driver(source, temporary, driver_source, **build_arguments)}
        arguments = () if scenario == "oom-survival" else (scenario,)
        if valid_clients_only and scenario != "oom-survival":
            arguments = (*arguments, "--valid-domain")
        executions = {side: run_driver(driver, arguments) for side, driver in drivers.items()}
        for side, execution in executions.items():
            harness.write_json(artifacts / f"{scenario}-{side}.json", execution)
            (artifacts / f"{scenario}-{side}.log").write_text(
                str(execution["stdout"]) + str(execution["stderr"]))
            (artifacts / f"{scenario}-{side}.trace").write_text(str(execution["stdout"]))
        for side, execution in executions.items():
            harness.require_success(execution, f"M4 operations {side} driver")
            if valid_clients_only and scenario != "oom-survival":
                validate_valid_domain_option(source_profile, side, execution)
        traces = {
            side: parse_operations_trace(str(execution["stdout"]), f"{side} operations trace")
            for side, execution in executions.items()
        }
        terminations = {
            name: {side: run_driver(driver, (f"abort:{name}",))["status"] for side, driver in drivers.items()}
            for name in (ABORT_SCENARIOS if scenario == "operations" and not valid_clients_only else ())
        }
        mode_traces = {}
        profile_receipt = None
        if scenario == "aligned-preservation" and not valid_clients_only:
            # Valid operation clients and invalid source preconditions are
            # separate observations; whole-trace equality must not mix them.
            run_operations_profiles(offline, API_PROFILES, ("operations", "api-modes"))
            receipt = read_operations_profiles(API_PROFILES, ("operations", "api-modes"))
            profile_receipt = engine.file_record(receipt.path)
            logs = receipt.path.parent / "logs"
            for profile in API_PROFILES:
                for side in ("c", "rust"):
                    execution = harness.read_json(logs / f"{profile}-api-modes-{side}.json")
                    mode_traces[f"{profile}.{side}"] = parse_operations_trace(
                        str(execution["stdout"]), f"{profile} {side} API trace")
    # Keep both raw traces beside the report so a mismatch can be located.
    artifacts.mkdir(parents=True, exist_ok=True)
    for side, execution in executions.items():
        (artifacts / f"{scenario}-{side}.trace").write_text(str(execution["stdout"]))
    for mode, trace in mode_traces.items():
        (artifacts / f"api-modes-{mode}.trace").write_text(
            "".join(f"{key}={value}\n" for key, value in trace.items())
        )
    for profile in ("release", "stat-1", "stat-2", "debug-1") if mode_traces else ():
        compare_operations_traces(mode_traces[f"{profile}.c"], mode_traces[f"{profile}.rust"])
    compare_operations_traces(traces["c"], traces["rust"],
                              private_source_profile=source_profile if valid_clients_only else None)
    unequal = {name: status for name, status in terminations.items() if status["c"] != status["rust"]}
    if unequal:
        raise harness.HarnessError(f"C/Rust operations termination mismatch: {unequal}")
    report = {
        "abort_scenarios": terminations,
        "compared_key_count": len(traces["c"]),
        "scenario": scenario,
        "api_profiles": mode_traces,
        "status": "passed",
        "trace": traces["c"],
    }
    if profile_receipt is not None:
        report["operation_profile_receipt"] = profile_receipt
    if valid_clients_only:
        report.update({"scope": "private-valid-client-differential-not-gate-qualification",
                       "build_profile": build_profile, "source_profile": source_profile, "upstream": pin,
                       "programs": {side: harness.artifact_record(driver) for side, driver in drivers.items()}})
    harness.write_json(artifacts / f"{scenario}.json", report)
    return report


API_PROFILES = ("release", "debug-1", "stat-1", "stat-2")
SOURCE_PROFILES = tuple(dict.fromkeys((*API_PROFILES, *GUARDED_API_PROFILE_BASES.values(),
                                     *GUARDED_API_PROFILE_BASES)))
PROFILE_SCENARIOS = (*DIFFERENTIAL_SCENARIOS, "api-modes")
OPERATIONS_RUNNER = "allocator-operation-profiles"
ASSERTION_CONTROLS = ("reallocarr-null", "reallocarr-zero-size", "aligned-invalid", "aligned-at-invalid")
SOURCE_CLIENT_CONTROLS = ("interior-api-modes", "usable-free-73", "usable-free-1000")



def operation_profile_parameters(profiles: Sequence[str], scenarios: Sequence[str]) -> dict[str, str]:
    if (not profiles or len(set(profiles)) != len(profiles)
            or any(profile not in (*API_PROFILES, "secure-1", "secure-2") for profile in profiles)):
        raise harness.HarnessError("unknown or duplicate operation profile selection")
    return {"profiles": ",".join(profiles), "scenarios": ",".join(scenarios),
            "workload": "valid-program-with-isolated-source-preconditions",
            "debug-source-guarded-precise": "1", "native-guarded-precise": "0",
            "source-debug-live-client-rejection": "CRABC-MI-DEBUG-ALIGNED-OFFSET-LIVE-CLIENT"}


def operation_receipts():
    specification = importlib.util.spec_from_file_location(
        "allocator_operation_receipts", harness.ROOT / "compat/x86_64/native_shadow_receipt.py")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def retain_operation_command(output: Path, name: str, record: Mapping[str, Any], cases: list):
    raw, log = output / f"{name}.json", output / f"{name}.log"
    harness.write_json(raw, record)
    log.write_text(str(record["stdout"]) + str(record["stderr"]))
    cases.append((name, record["status"], [raw, log]))


def observe_operations_profile(output: Path, profile: str, scenario: str, drivers: Mapping[str, Path],
                               cases: list, *, valid_domain: bool = False) -> dict[str, Any]:
    arguments = () if scenario == "oom-survival" else (scenario,)
    if valid_domain:
        arguments = (*arguments, "--valid-domain")
    executions = {side: run_driver(drivers[side], arguments) for side in ("c", "rust")}
    for side, record in executions.items():
        retain_operation_command(output, f"{profile}-{scenario}-{side}", record, cases)
    if valid_domain:
        for side, record in executions.items():
            validate_valid_domain_option(profile, side, record)
    controls, control_errors = {}, []
    if valid_domain and scenario == "operations":
        for control in ASSERTION_CONTROLS:
            records = {side: run_driver(drivers[side], (f"precondition:{control}",))
                       for side in ("c", "rust")}
            paths = []
            for side, record in records.items():
                name = f"{profile}-precondition-{control}-{side}"
                retained = []
                retain_operation_command(output, name, record, retained)
                paths.extend(retained[0][2])
            try:
                compare_assertion_control(profile, control, records["c"], records["rust"])
            except harness.HarnessError as error:
                control_errors.append(str(error))
                cases.append((f"{profile}-precondition-{control}-comparison", 1, paths))
            else:
                cases.append((f"{profile}-precondition-{control}-comparison", 0, paths))
            controls[control] = {side: record["status"] for side, record in records.items()}
    if valid_domain and scenario == "operations":
        for control in SOURCE_CLIENT_CONTROLS:
            records, paths = {}, []
            for condition in ("original", "oracle"):
                records[condition] = {}
                arguments = (f"source-client:{control}",) + (("--valid-domain",) if condition == "oracle" else ())
                for side in ("c", "rust"):
                    record = run_driver(drivers[side], arguments)
                    records[condition][side] = record
                    retained = []
                    retain_operation_command(output, f"{profile}-source-client-{control}-{condition}-{side}", record, retained)
                    paths.extend(retained[0][2])
            try:
                compare_source_client_control(profile, control, records["original"], records["oracle"])
            except harness.HarnessError as error:
                control_errors.append(str(error))
                cases.append((f"{profile}-source-client-{control}-comparison", 1, paths))
            else:
                cases.append((f"{profile}-source-client-{control}-comparison", 0, paths))
    termination = {}
    for name in ABORT_SCENARIOS if scenario == "operations" else ():
        records = {side: run_driver(drivers[side], (f"abort:{name}",)) for side in ("c", "rust")}
        for side, record in records.items():
            retain_operation_command(output, f"{profile}-{name}-{side}", record, cases)
        termination[name] = {side: record["status"] for side, record in records.items()}
        if records["c"]["status"] != -6 or records["rust"]["status"] != -6:
            raise harness.HarnessError(f"{profile} {name} did not terminate with the source SIGABRT")
    for side, record in executions.items():
        harness.require_success(record, f"{profile} {scenario} {side} workload")
    traces = {side: parse_operations_trace(str(record["stdout"]), f"{profile} {scenario} {side}")
              for side, record in executions.items()}
    compare_operations_traces(traces["c"], traces["rust"])
    if control_errors:
        raise harness.HarnessError("; ".join(control_errors))
    return {"trace": traces["c"], "abort_scenarios": termination, "precondition_controls": controls}


def validate_valid_domain_option(profile: str, side: str, record: Mapping[str, Any]) -> None:
    expected = int(profile.startswith("debug-") and side == "c")
    markers = re.findall(r"^valid-domain guarded_precise=(\d+)$", str(record.get("stderr", "")), re.MULTILINE)
    if markers != [str(expected)]:
        raise harness.HarnessError(f"{profile} {side} valid-client oracle option differs")


def validate_operation_build(record: Mapping[str, Any], inputs: Mapping[str, Any], profile: str,
                             family: str, fixture: str, side: str):
    source, output = Path(inputs["source_directory"]), Path(inputs["output_directory"])
    directory = output / profile / family
    if side == "c":
        expected = [inputs["compiler"], "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                    "-DCRABC_MI_M4_SOURCE_CANARY=1", *api_profile_flags(profile),
                    "-I", str(source / "include"), str(output / fixture), str(source / "src/static.c"),
                    "-pthread", "-o", str(directory / "operations-c")]
    else:
        library = output / profile / "cargo-target" / RUST_TARGET / "release" / ADAPTER_STATICLIB
        expected = [inputs["compiler"], "-std=c11", "-O2", "-I", str(source / "include"),
                    str(output / fixture), str(library), "-pthread", "-o", str(directory / "operations-rust")]
    if record.get("status") != 0 or record.get("command") != expected:
        raise harness.HarnessError(f"{profile} {family} {side} compiler authority changed")


def source_debug_option_scope(record: Mapping[str, Any], inputs: Mapping[str, Any]) -> None:
    source = Path(inputs["source_directory"])
    command = [inputs["compiler"], "-std=c11", *api_profile_flags("debug-1"), "-DMI_LIBC_MUSL=1",
               "-I", str(source / "include"), "-E", str(source / "src/static.c")]
    preprocessed = str(record.get("stdout", ""))
    # The other two occurrences declare the option and its default descriptor.
    # A second executable use would change the meaning of the oracle option.
    if (record.get("status") != 0 or record.get("command") != command
            or preprocessed.count("mi_option_guarded_precise") != 3
            or len(re.findall(r"mi_option_is_enabled\s*\(\s*mi_option_guarded_precise\s*\)", preprocessed)) != 1):
        raise harness.HarnessError("debug source oracle option has an unproved active use or compiler condition")


def read_operations_profiles(profiles: Sequence[str], scenarios: Sequence[str], *, replay: bool = False,
                             runner: str = OPERATIONS_RUNNER):
    """Reconstruct valid workloads and isolated controls from authenticated commands and products."""
    receipts = operation_receipts()
    receipt = receipts.read_receipt(harness.ROOT, runner)
    if dict(receipt.parameters) != operation_profile_parameters(profiles, scenarios):
        raise harness.HarnessError("operation receipt profile or scenario selection changed")
    products, logs = receipt.path.parent / "products", receipt.path.parent / "logs"
    inputs = harness.read_json(products / "inputs.json")
    if (inputs["source"] != dict(receipt.source) or inputs["upstream"] != harness.load_pin()
            or inputs["profiles"] != list(profiles) or inputs["scenarios"] != list(scenarios)
            or inputs["compiler"] != harness.require_tool("musl-gcc")
            or inputs["cargo"] != harness.require_tool("cargo")):
        raise harness.HarnessError("operation receipt source, tool, or profile authority changed")
    if harness.sha256_file(products / "upstream-archive") != harness.load_pin()["sha256"]:
        raise harness.HarnessError("operation receipt pinned archive changed")
    native = harness.read_json(products / "native-execution-provenance.json")
    execution = harness.require_native_x86_64(require_image_identity=True)
    harness.validate_native_execution_provenance(native, expected_image_id=execution["image_id"])
    if native != inputs["execution"]:
        raise harness.HarnessError("operation receipt initial execution identity changed")
    for fixture in (OPERATIONS_DRIVER, OOM_SURVIVAL_DRIVER):
        if (products / fixture.name).read_bytes() != fixture.read_bytes():
            raise harness.HarnessError("operation receipt workload fixture changed")
    if "debug-1" in profiles:
        source_debug_option_scope(harness.read_json(products / "debug-source-preprocess.json"), inputs)
    original = Path(inputs["output_directory"])
    if (not original.is_relative_to(ARTIFACTS) or not Path(inputs["source_directory"]).is_relative_to(original)):
        raise harness.HarnessError("operation receipt compiler outputs escaped owned artifacts")
    expected_cases = []
    for profile in profiles:
        adapter = harness.read_json(products / f"{profile}-adapter-build.json")
        target = original / profile / "cargo-target"
        expected = [inputs["cargo"], "build", "--locked", "--release", "--message-format=json",
                    "--target", RUST_TARGET, "-p", ADAPTER_PACKAGE, "--target-dir", str(target),
                    *(("--features", f"crabc-mimalloc/mi-{profile}") if profile != "release" else ())]
        if adapter.get("status") != 0 or adapter.get("command") != expected:
            raise harness.HarnessError(f"{profile} adapter compiler authority changed")
        library = target / RUST_TARGET / "release" / ADAPTER_STATICLIB
        artifacts = [json.loads(line) for line in str(adapter["stdout"]).splitlines() if line.startswith("{")]
        if not any(item.get("reason") == "compiler-artifact" and str(library) in item.get("filenames", [])
                   for item in artifacts):
            raise harness.HarnessError(f"{profile} adapter lacks compiler-emitted static archive authority")
        record = adapter.get("artifact", {})
        if (record.get("path") != harness.relative(library)
                or record.get("sha256") != harness.sha256_file(products / f"{profile}-adapter.a")
                or record.get("bytes") != (products / f"{profile}-adapter.a").stat().st_size):
            raise harness.HarnessError(f"{profile} compiler archive differs from the retained product")
        for family, fixture in (("operations", OPERATIONS_DRIVER), ("oom-survival", OOM_SURVIVAL_DRIVER)):
            for side in ("c", "rust"):
                binary = products / f"{profile}-{family}-{side}"
                header = harness.command_record([harness.require_tool("readelf"), "-h", str(binary)], cwd=products)
                harness.require_success(header, "operation retained ELF inspection")
                harness.parse_elf_identity(str(header["stdout"]), "x86_64")
            validate_operation_build(harness.read_json(products / f"{profile}-{family}-c-build.json"),
                                     inputs, profile, family, fixture.name, "c")
            name = f"{profile}-{family}-rust-link"
            validate_operation_build(harness.read_json(logs / f"{name}.json"),
                                     inputs, profile, family, fixture.name, "rust")
            expected_cases.append(name)
            for scenario in scenarios:
                if (scenario == "oom-survival") != (family == "oom-survival"):
                    continue
                observed = {}
                for side in ("c", "rust"):
                    name = f"{profile}-{scenario}-{side}"
                    expected_cases.append(name)
                    record = harness.read_json(logs / f"{name}.json")
                    binary = original / profile / family / f"operations-{side}"
                    arguments = ["--valid-domain"] if scenario == "oom-survival" else [scenario, "--valid-domain"]
                    validate_valid_domain_option(profile, side, record)
                    if record.get("status") != 0 or record.get("command") != [str(binary), *arguments]:
                        raise harness.HarnessError(f"{name} original execution authority changed")
                    observed[side] = parse_operations_trace(str(record["stdout"]), name)
                compare_operations_traces(observed["c"], observed["rust"])
                for control in ASSERTION_CONTROLS if scenario == "operations" else ():
                    records = {}
                    for side in ("c", "rust"):
                        name = f"{profile}-precondition-{control}-{side}"
                        record = harness.read_json(logs / f"{name}.json")
                        binary = original / profile / family / f"operations-{side}"
                        if record.get("command") != [str(binary), f"precondition:{control}"]:
                            raise harness.HarnessError(f"{name} original precondition command changed")
                        records[side] = record
                    compare_assertion_control(profile, control, records["c"], records["rust"])
                    expected_cases.append(f"{profile}-precondition-{control}-comparison")
                for control in SOURCE_CLIENT_CONTROLS if scenario == "operations" else ():
                    records = {}
                    for condition in ("original", "oracle"):
                        records[condition] = {}
                        for side in ("c", "rust"):
                            name = f"{profile}-source-client-{control}-{condition}-{side}"
                            record = harness.read_json(logs / f"{name}.json")
                            binary = original / profile / family / f"operations-{side}"
                            arguments = [f"source-client:{control}"] + (["--valid-domain"] if condition == "oracle" else [])
                            if record.get("command") != [str(binary), *arguments]:
                                raise harness.HarnessError(f"{name} live-client condition command changed")
                            records[condition][side] = record
                    compare_source_client_control(profile, control, records["original"], records["oracle"])
                    expected_cases.append(f"{profile}-source-client-{control}-comparison")
                for abort in ABORT_SCENARIOS if scenario == "operations" else ():
                    for side in ("c", "rust"):
                        name = f"{profile}-{abort}-{side}"
                        expected_cases.append(name)
                        record = harness.read_json(logs / f"{name}.json")
                        binary = original / profile / family / f"operations-{side}"
                        if record.get("status") != -6 or record.get("command") != [str(binary), f"abort:{abort}"]:
                            raise harness.HarnessError(f"{name} source termination authority changed")
    if receipt.case_ids() != expected_cases:
        raise harness.HarnessError("operation receipt full workload roster changed")
    if replay:
        execution = harness.require_native_x86_64(require_image_identity=True)
        harness.validate_native_execution_provenance(native, expected_image_id=execution["image_id"])
        harness.TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        output = Path(tempfile.mkdtemp(prefix="operation-profiles-replay-", dir=harness.TEMP_ROOT))
        for profile in profiles:
            for family in ("operations", "oom-survival"):
                drivers = {}
                for side in ("c", "rust"):
                    binary = output / f"{profile}-{family}-{side}"
                    shutil.copyfile(products / binary.name, binary)
                    binary.chmod(0o755)
                    drivers[side] = binary
                for scenario in scenarios:
                    if (scenario == "oom-survival") == (family == "oom-survival"):
                        observe_operations_profile(output, profile, scenario, drivers, [], valid_domain=True)
        print(f"operation profile original product replay retained at {output}")
    return receipt


def run_operations_profiles(offline: bool, profiles: Sequence[str], scenarios: Sequence[str], *,
                            runner: str = OPERATIONS_RUNNER) -> dict[str, Any]:
    """Retain every valid observation and isolated precondition before admitting a cohort."""
    operation_profile_parameters(profiles, scenarios)
    receipts = operation_receipts()
    execution = harness.require_native_x86_64(require_image_identity=True)
    seal = receipts.source_seal(harness.ROOT)
    if seal["worktree_sha256"] != __import__("hashlib").sha256(b"").hexdigest():
        raise harness.HarnessError("operation profile qualification requires a clean frozen source")
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="profiles-", dir=ARTIFACTS))
    source = harness.safe_extract(archive, output / "source", pin["archive_root"])
    products, cases, observed, errors = {"upstream-archive": archive}, [], {}, []
    inputs = {"source": seal, "execution": execution, "upstream": pin,
              "profiles": list(profiles), "scenarios": list(scenarios), "source_directory": str(source),
              "output_directory": str(output),
              "compiler": harness.require_tool("musl-gcc"), "cargo": harness.require_tool("cargo")}
    if "debug-1" in profiles:
        command = [inputs["compiler"], "-std=c11", *api_profile_flags("debug-1"), "-DMI_LIBC_MUSL=1",
                   "-I", str(source / "include"), "-E", str(source / "src/static.c")]
        preprocessing = harness.command_record(command, cwd=source)
        path = output / "debug-source-preprocess.json"
        harness.write_json(path, preprocessing)
        products[path.name] = path
        source_debug_option_scope(preprocessing, inputs)
    for fixture in (OPERATIONS_DRIVER, OOM_SURVIVAL_DRIVER):
        retained = output / fixture.name
        shutil.copy2(fixture, retained)
        products[fixture.name] = retained
    for profile in profiles:
        directory = output / profile
        directory.mkdir()
        try:
            library = build_adapter_library(directory, profile)
            retained_library = directory / "adapter.a"
            shutil.copy2(library, retained_library)
            products[f"{profile}-adapter.a"] = retained_library
            products[f"{profile}-adapter-build.json"] = directory / "adapter-build.json"
            for family, fixture in (("operations", OPERATIONS_DRIVER), ("oom-survival", OOM_SURVIVAL_DRIVER)):
                family_directory = directory / family
                family_directory.mkdir()
                retained = output / fixture.name
                c = build_c_driver(source, family_directory, retained, profile)
                rust = family_directory / "operations-rust"
                command = [inputs["compiler"], "-std=c11", "-O2", "-I", str(source / "include"),
                           str(retained), str(library), "-pthread", "-o", str(rust)]
                link = harness.command_record(command, cwd=source)
                retain_operation_command(output, f"{profile}-{family}-rust-link", link, cases)
                harness.require_success(link, f"{profile} {family} native link")
                products[f"{profile}-{family}-c"] = c
                products[f"{profile}-{family}-rust"] = rust
                products[f"{profile}-{family}-c-build.json"] = family_directory / "c-build.json"
                for scenario in scenarios:
                    if (scenario == "oom-survival") != (family == "oom-survival"):
                        continue
                    try:
                        observed[f"{profile}.{scenario}"] = observe_operations_profile(
                            output, profile, scenario, {"c": c, "rust": rust}, cases, valid_domain=True)
                        print(f"{profile}.{scenario}: matched valid workload and source controls", flush=True)
                    except harness.HarnessError as error:
                        errors.append(f"{profile}.{scenario}: {error}")
                        print(f"{profile}.{scenario}: FAILED {error}", flush=True)
        except harness.HarnessError as error:
            errors.append(f"{profile} build: {error}")
        finally:
            # Compiler products and original command records are retained above;
            # incremental build caches are disposable after all links finish.
            shutil.rmtree(directory / "cargo-target", ignore_errors=True)
    inputs_path = output / "inputs.json"
    harness.write_json(inputs_path, inputs)
    products["inputs.json"] = inputs_path
    native = output / "native-execution-provenance.json"
    harness.write_json(native, harness.native_execution_attestation(
        execution, harness.require_native_x86_64(require_image_identity=True)))
    products["native-execution-provenance.json"] = native
    result = {"profiles": list(profiles), "scenarios": list(scenarios), "observations": observed,
              "errors": errors, "status": "failed" if errors else "passed"}
    harness.write_json(output / "results.json", result)
    if receipts.source_seal(harness.ROOT) != seal:
        raise harness.HarnessError("source changed during operation profile cohort")
    # Abort exits remain raw command records; the comparison is a successful check.
    positive_cases = [(name, 0 if any(name.endswith(f"-{abort}-{side}")
                      for abort in ABORT_SCENARIOS for side in ("c", "rust")) else status, logs)
                      for name, status, logs in cases]
    receipts.write_receipt(harness.ROOT, runner, output, products, positive_cases,
        operation_profile_parameters(profiles, scenarios), not errors)
    if errors:
        raise harness.HarnessError(f"operation profile cohort failed; original raw retained at {output}: " + "; ".join(errors))
    return result


# ---------------------------------------------------------------------------
# upstream:test-api
# ---------------------------------------------------------------------------

TEST_API_CHECK = re.compile(
    r"^test: ([A-Za-z0-9_-]+)\.\.\.  (?:[^\n]*?  )?(ok\.|FAILED: [^\n]+)$", re.MULTILINE,
)


def parse_upstream_test_api_checks(output: str) -> dict[str, bool]:
    """Require one distinct terminal outcome for every printed test line."""

    test_lines = [line for line in output.splitlines() if line.startswith("test:")]
    if not test_lines:
        raise harness.HarnessError("upstream test-api printed no test lines")
    checks: dict[str, bool] = {}
    for line in test_lines:
        match = TEST_API_CHECK.fullmatch(line)
        if match is None:
            raise harness.HarnessError(f"upstream test-api has a malformed test line: {line}")
        name, verdict = match.groups()
        if name in checks:
            raise harness.HarnessError(f"upstream test-api repeated test: {name}")
        checks[name] = verdict == "ok."
    summary = harness.parse_upstream_api_test_summary(output)
    if len(checks) != summary["succeeded"] or not all(checks.values()):
        raise harness.HarnessError("upstream test-api outcomes differ from its summary")
    return checks


def run_upstream_test_api(offline: bool) -> dict[str, Any]:
    """Link the unmodified pinned `test/test-api.c` against the native adapter only.

    Its checks print to stderr; each must report `ok.` and the summary must
    report no failure. Its complete interface needs Heap, reservation,
    option and statistics exports as well as allocation operations.
    """

    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory("crabc-mimalloc-x86_64-m4-test-api-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        library = build_adapter_library(temporary)
        binary = temporary / "test-api"
        link = harness.command_record(
            [
                harness.require_tool("musl-gcc"), "-std=c11", *harness.CONFIGURATION_PROFILES["release"],
                "-I", str(source / "include"), "-I", str(source / "test"),
                str(source / "test/test-api.c"), str(library), "-pthread", "-o", str(binary),
            ],
            cwd=source,
        )
        harness.require_success(link, "upstream test-api link against the native adapter")
        execution = harness.command_record((str(binary),), cwd=temporary, env={}, timeout_seconds=600)
    output = str(execution["stderr"])
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "test-api.log").write_text(str(execution["stdout"]) + output)
    if execution["status"] != 0:
        raise harness.HarnessError(
            f"upstream test-api failed (status {execution['status']}): {output[-400:]}"
        )
    checks = parse_upstream_test_api_checks(output)
    report = {"checks": checks, "status": "passed"}
    harness.write_json(ARTIFACTS / "test-api.json", report)
    return report


# ---------------------------------------------------------------------------
# adapter:export-boundary
# ---------------------------------------------------------------------------

def m4_external_functions(contract: Mapping[str, Any], api: Mapping[str, Any]) -> list[str]:
    """Selected interfaces that the pinned header declares as functions."""

    kinds = {item["name"]: item.get("kind") for item in api["items"]}
    return sorted(
        name for gate in contract["gates"] for name in gate["items"] if kinds.get(name) == "external-function"
    )


def pinned_external_functions(api: Mapping[str, Any]) -> set[str]:
    """Every function the pinned header declares."""

    return {item["name"] for item in api["items"] if item.get("kind") == "external-function"}


def defined_global_symbols(nm_output: str) -> set[str]:
    """Names from `nm -g --defined-only` (`[address] type name` lines)."""

    symbols: set[str] = set()
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and len(fields[-2]) == 1:
            symbols.add(fields[-1])
    return symbols


def adapter_probe_source(functions: Sequence[str]) -> str:
    """A C unit that names every function through the pinned header."""

    table = "".join(f"  (void (*)(void))&{name},\n" for name in functions)
    return (
        "#include <stdio.h>\n#include \"mimalloc.h\"\n"
        f"static void (*const table[])(void) = {{\n{table}}};\n"
        "int main(void) {\n"
        "  size_t present = 0;\n"
        "  for (size_t i = 0; i < sizeof table / sizeof table[0]; i++) { present += (table[i] != NULL); }\n"
        "  void* p = mi_malloc(64);\n  mi_free(p);\n"
        "  printf(\"%zu %d\\n\", present, p != NULL);\n  return 0;\n}\n"
    )


def run_adapter_boundary(offline: bool) -> dict[str, Any]:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    contract = harness.read_json(CONTRACT)
    api = harness.read_json(harness.ALLOCATOR_ROOT / "api-v3.5.0.json")
    functions = m4_external_functions(contract, api)
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory("crabc-mimalloc-x86_64-m4-adapter-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        library = build_adapter_library(temporary)
        symbols = harness.command_record((harness.require_tool("nm"), "-g", "--defined-only", str(library)), cwd=temporary)
        harness.require_success(symbols, "M4 adapter symbol listing")
        probe_source = temporary / "adapter-probe.c"
        probe_source.write_text(adapter_probe_source(functions))
        probe = temporary / "adapter-probe"
        link = harness.command_record(
            [
                harness.require_tool("musl-gcc"), "-std=c11", "-Werror=implicit-function-declaration",
                "-I", str(source / "include"), str(probe_source), str(library), "-pthread", "-o", str(probe),
            ],
            cwd=temporary,
        )
        harness.require_success(link, "M4 adapter probe link")
        execution = harness.command_record((str(probe),), cwd=temporary, env={})
        harness.require_success(execution, "M4 adapter probe execution")
    defined = defined_global_symbols(str(symbols["stdout"]))
    exported = sorted(name for name in defined if name.startswith("mi_"))
    # The adapter is shared across allocator checks: it must export every
    # selected operation and nothing outside the pinned external API.
    missing = sorted(set(functions) - set(exported))
    unpinned = sorted(set(exported) - pinned_external_functions(api))
    if missing or unpinned:
        raise harness.HarnessError(
            "M4 adapter mi_* exports are not the M4 functions within the pinned API: "
            f"missing {missing}, outside the pinned API {unpinned}"
        )
    interposed = sorted(defined & C_ALLOCATOR_NAMES)
    if interposed:
        raise harness.HarnessError(f"M4 adapter defines C allocator entries: {interposed}")
    # Pinned C mimalloc defines its internal entries as `_mi_*` globals; none
    # may be present, so no C allocator object reached the archive.
    c_internal = sorted(name for name in defined if name.startswith("_mi_"))
    if c_internal:
        raise harness.HarnessError(f"M4 adapter contains C mimalloc symbols: {c_internal[:8]}")
    if str(execution["stdout"]).split() != [str(len(functions)), "1"]:
        raise harness.HarnessError(f"M4 adapter probe reported {execution['stdout']!r}")
    report = {"exported_functions": exported, "status": "passed"}
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    harness.write_json(ARTIFACTS / "adapter-boundary.json", report)
    return report


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
    mode.add_argument("--operations-matrix", action="store_true",
        help="run every unchanged operation scenario in all four source profiles")
    mode.add_argument("--check", action="store_true",
        help="validate the contract and inventory closure without executing evidence")
    mode.add_argument("--gate", choices=GATE_IDS, help="execute only this gate's runnable evidence")
    mode.add_argument("--native-tests", action="store_true",
        help="run the focused native-engine integration regressions")
    mode.add_argument("--adapter-boundary", action="store_true",
        help="audit the native adapter's export boundary and header linkage")
    mode.add_argument("--differential", choices=PROFILE_SCENARIOS,
        help="run one shared-driver pinned-C/native-adapter differential scenario")
    mode.add_argument("--upstream-test-api", action="store_true",
        help="link the unmodified pinned test-api.c against the native adapter and run it")
    parser.add_argument("--read", action="store_true", help="authenticate the full operation-profile receipt")
    parser.add_argument("--replay", action="store_true", help="authenticate and replay retained operation-profile products")
    parser.add_argument("--offline", action="store_true", help="require the verified archive in the local cache")
    parser.add_argument("--build-profile", choices=("release", "debug"), default="release")
    parser.add_argument("--source-profile", choices=SOURCE_PROFILES, default="release")
    parser.add_argument("--valid-clients-only", action="store_true",
                        help="retain a private differential without precondition controls or profile qualification")
    arguments = parser.parse_args(argv)
    if (arguments.build_profile != "release" or arguments.source_profile != "release" or arguments.valid_clients_only) and arguments.differential is None:
        parser.error("build/source profile and valid-client selection require --differential")
    if (arguments.read or arguments.replay) and not arguments.operations_matrix:
        parser.error("--read and --replay require --operations-matrix")
    if arguments.operations_matrix:
        if arguments.read or arguments.replay:
            read_operations_profiles(API_PROFILES, PROFILE_SCENARIOS, replay=arguments.replay)
            print("M4 full operation profile receipt authenticated")
            return 0
        run_operations_profiles(arguments.offline, API_PROFILES, PROFILE_SCENARIOS)
        print("M4 full operation profile cohort passed")
        return 0
    if arguments.native_tests:
        report = run_native_tests()
        print(f"M4 native-engine regressions passed: {len(report['targets'])} targets")
        return 0
    if arguments.adapter_boundary:
        report = run_adapter_boundary(arguments.offline)
        print(f"M4 adapter boundary passed: {len(report['exported_functions'])} functions")
        return 0
    if arguments.upstream_test_api:
        report = run_upstream_test_api(arguments.offline)
        print(f"upstream test-api passed: {len(report['checks'])} checks")
        return 0
    if arguments.differential is not None:
        report = run_operations_differential(arguments.offline, arguments.differential,
            build_profile=arguments.build_profile, source_profile=arguments.source_profile,
            valid_clients_only=arguments.valid_clients_only)
        print(f"M4 {arguments.differential} differential passed: {report['compared_key_count']} keys")
        return 0
    contract, summary = load_summary()
    if arguments.check:
        print(
            f"M4 gate contract valid: {summary['item_count']} interface items in "
            f"{len(summary['gate_ids'])} gates ({len(summary['excluded_items'])} excluded to their owners); "
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
    report["provenance"] = report_provenance(report)
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
            f"M4 unmet: {len(report['unmet_required'])}/{len(report['gates'])} required gates; "
            f"report {harness.relative(report_path)}",
            file=sys.stderr,
        )
        return 1
    print("M4 passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
