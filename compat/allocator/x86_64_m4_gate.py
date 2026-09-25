#!/usr/bin/env python3
"""Fail-closed native Linux/x86-64 gate for allocator Milestone 4.

M4 is "calloc, realloc, aligned operations, usable size,
medium/large/singleton, collection, OOM/failure preservation, C adapter, and
applicable upstream operation tests" (plan.md Milestones). The reviewed
contract `m4-gate-x86_64-v3.5.0.json` selects the M4 interface items from the
pinned API applicability inventory, disjoint from the M6 and M7 contracts,
partitions them into gates, and names the evidence each gate requires. An
applicable item the selection reaches but another milestone owns is listed in
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
- `--adapter-boundary` audits the native adapter static library: its defined
  `mi_*` globals include every M4 external function and only functions the
  pinned header declares (the M6 and M7 gates add theirs to the same
  adapter), it defines no libc allocator entry or C mimalloc `_mi_*` internal, and a C probe that
  takes every function's address through the pinned `mimalloc.h` links
  against it alone and runs.
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
OPERATIONS_TRACE_BEGIN = "CRABC_MI_M4_OPERATIONS_TRACE_BEGIN"
OPERATIONS_TRACE_END = "CRABC_MI_M4_OPERATIONS_TRACE_END"
# Driver scenarios, each one evidence entry run in fresh processes.
DIFFERENTIAL_SCENARIOS = ("operations", "page-kinds", "collection", "oom", "threads")
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
    """Items that another milestone contract already owns, by owning contract."""

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
    # A sibling-owned item is not M4's; an excluded one names its owner.
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
    harness.require_success(execution, "M4 native-engine regressions")
    output = str(execution["stdout"]) + "\n" + str(execution["stderr"])
    # Every target reports its own libtest summary; a target that ran no test
    # is a selection defect, not a pass.
    summaries = [line for line in output.splitlines() if line.startswith("test result: ok.")]
    if len(summaries) != len(NATIVE_TESTS) or any(" 0 passed" in line for line in summaries):
        raise harness.HarnessError("M4 native-engine regressions did not run one nonempty suite per target")
    report = {"command": execution["command"], "status": "passed", "targets": list(NATIVE_TESTS)}
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


def compare_operations_traces(c_trace: Mapping[str, str], rust_trace: Mapping[str, str]) -> None:
    """Require equal traces, reporting differences in C trace order.

    Allocation ids and reuse relations cascade, so the first differing key
    is the one that locates a divergence.
    """

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


def build_c_driver(source: Path, temporary: Path) -> Path:
    """Link the shared driver against the pinned release `src/static.c`."""

    compiler = harness.require_tool("musl-gcc")
    driver = temporary / "operations-c"
    build = harness.command_record(
        [
            compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
            *harness.CONFIGURATION_PROFILES["release"], "-I", str(source / "include"),
            str(OPERATIONS_DRIVER), str(source / "src/static.c"), "-pthread", "-o", str(driver),
        ],
        cwd=source,
    )
    harness.require_success(build, "M4 operations C driver build")
    return driver


def build_adapter_library(temporary: Path) -> Path:
    """Build the native adapter static library in this run's own target."""

    target_dir = temporary / "cargo-target"
    build = harness.command_record(
        [
            harness.require_tool("cargo"), "build", "--locked", "--release", "--target", RUST_TARGET,
            "-p", ADAPTER_PACKAGE, "--target-dir", str(target_dir),
        ],
        cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=EVIDENCE_TIMEOUT_SECONDS,
    )
    harness.require_success(build, "M4 native adapter build")
    return target_dir / RUST_TARGET / "release" / ADAPTER_STATICLIB


def build_rust_driver(source: Path, temporary: Path) -> Path:
    """Link the same driver, unchanged, against the native adapter only."""

    library = build_adapter_library(temporary)
    driver = temporary / "operations-rust"
    link = harness.command_record(
        [
            harness.require_tool("musl-gcc"), "-std=c11", "-O2", "-I", str(source / "include"),
            str(OPERATIONS_DRIVER), str(library), "-pthread", "-o", str(driver),
        ],
        cwd=source,
    )
    harness.require_success(link, "M4 operations Rust driver link")
    return driver


def run_driver(driver: Path, arguments: Sequence[str] = ()) -> dict[str, Any]:
    return harness.command_record((str(driver), *arguments), cwd=driver.parent, env={}, timeout_seconds=600)


def run_operations_differential(offline: bool, scenario: str) -> dict[str, Any]:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory("crabc-mimalloc-x86_64-m4-operations-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        drivers = {"c": build_c_driver(source, temporary), "rust": build_rust_driver(source, temporary)}
        executions = {side: run_driver(driver, (scenario,)) for side, driver in drivers.items()}
        for side, execution in executions.items():
            harness.require_success(execution, f"M4 operations {side} driver")
        traces = {
            side: parse_operations_trace(str(execution["stdout"]), f"{side} operations trace")
            for side, execution in executions.items()
        }
        terminations = {
            name: {side: run_driver(driver, (f"abort:{name}",))["status"] for side, driver in drivers.items()}
            for name in (ABORT_SCENARIOS if scenario == "operations" else ())
        }
    # Keep both raw traces beside the report so a mismatch can be located.
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    for side, execution in executions.items():
        (ARTIFACTS / f"{scenario}-{side}.trace").write_text(str(execution["stdout"]))
    compare_operations_traces(traces["c"], traces["rust"])
    unequal = {name: status for name, status in terminations.items() if status["c"] != status["rust"]}
    if unequal:
        raise harness.HarnessError(f"C/Rust operations termination mismatch: {unequal}")
    report = {
        "abort_scenarios": terminations,
        "compared_key_count": len(traces["c"]),
        "scenario": scenario,
        "status": "passed",
        "trace": traces["c"],
    }
    harness.write_json(ARTIFACTS / f"{scenario}.json", report)
    return report


# ---------------------------------------------------------------------------
# adapter:export-boundary
# ---------------------------------------------------------------------------

def m4_external_functions(contract: Mapping[str, Any], api: Mapping[str, Any]) -> list[str]:
    """The M4 gate items the pinned header declares as functions."""

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
    # The adapter is shared with the M6 and M7 gates: it must export every M4
    # function and nothing outside the pinned header's external functions.
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
    mode.add_argument("--check", action="store_true",
        help="validate the contract and inventory closure without executing evidence")
    mode.add_argument("--gate", choices=GATE_IDS, help="execute only this gate's runnable evidence")
    mode.add_argument("--native-tests", action="store_true",
        help="run the focused native-engine integration regressions")
    mode.add_argument("--adapter-boundary", action="store_true",
        help="audit the native adapter's export boundary and header linkage")
    mode.add_argument("--differential", choices=DIFFERENTIAL_SCENARIOS,
        help="run one shared-driver pinned-C/native-adapter differential scenario")
    parser.add_argument("--offline", action="store_true", help="require the verified archive in the local cache")
    arguments = parser.parse_args(argv)
    if arguments.native_tests:
        report = run_native_tests()
        print(f"M4 native-engine regressions passed: {len(report['targets'])} targets")
        return 0
    if arguments.adapter_boundary:
        report = run_adapter_boundary(arguments.offline)
        print(f"M4 adapter boundary passed: {len(report['exported_functions'])} functions")
        return 0
    if arguments.differential is not None:
        report = run_operations_differential(arguments.offline, arguments.differential)
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
