#!/usr/bin/env python3
"""Fail-closed native Linux/x86-64 allocator gate.

The contract selects applicable interfaces and compile-time modes from the
pinned API inventory, partitions them into gates, and names required evidence.

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
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import run as harness
import perf_engine_x86_64 as engine
import perf_integrated_x86_64 as integrated


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
DELAYED_OUTPUT_SATURATION_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_delayed_output_saturation_oracle.c"
DELAYED_OUTPUT_SATURATION_TEST = "diagnostic_output::tests::delayed_output_saturation_trace_for_pinned_c_comparison"
DELAYED_OUTPUT_SATURATION_TRACE_BEGIN = "CRABC_MI_M7_DELAYED_OUTPUT_SATURATION_TRACE_BEGIN"
DELAYED_OUTPUT_SATURATION_TRACE_END = "CRABC_MI_M7_DELAYED_OUTPUT_SATURATION_TRACE_END"
# Every environment image both halves must replay. A scenario absent from both
# traces would otherwise compare equal.
OPTIONS_SCENARIOS = (
    "empty", "show_errors_off", "canonical", "legacy", "invalid", "verbose", "guarded_boolean",
    "guarded_numeric", "size_without_digits", "cap", "overlong",
)
OPTIONS_ERROR_SCENARIOS = ("hidden", "disabled", "capped", "verbose")
# Recursive-output scenarios: a registered callback that reads `verbose` and
# re-enters `_mi_warning_message` during startup and one direct warning.
OPTIONS_RECURSION_SCENARIOS = ("invalid_verbose", "show_errors", "capped")
ERROR_SITES_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_error_sites_oracle.c"
ERROR_SITES_RUST_TEST = "native_error_sites"
ERROR_SITES_TRACE_BEGIN = "CRABC_MI_M7_ERROR_SITES_TRACE_BEGIN"
ERROR_SITES_TRACE_END = "CRABC_MI_M7_ERROR_SITES_TRACE_END"
# Both halves run with the error gate open so every reached site is shown.
# The reservation size exceeds `MI_MAX_ALLOC_SIZE` once rounded to a slice.
ERROR_SITES_ENVIRONMENT = {
    "mimalloc_show_errors": "1", "mimalloc_reserve_os_memory": "9223372036854775807",
}
# Every request both halves must report, on the main thread and a worker.
ERROR_SITE_CASES = tuple(
    prefix + case
    for prefix in ("", "worker_")
    for case in (
        "malloc_too_large", "aligned_bad_alignment", "aligned_too_large",
        "aligned_large_alignment_offset", "aligned_overallocation_too_large", "malloc_ordinary",
    )
)
OPTION_PROFILES_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_option_profiles_oracle.c"
OPTIONAL_ISA_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_optional_isa_oracle.c"
OPTIONAL_ISA_TRACE_BEGIN = "CRABC_MI_M7_OPTIONAL_ISA_TRACE_BEGIN"
OPTIONAL_ISA_TRACE_END = "CRABC_MI_M7_OPTIONAL_ISA_TRACE_END"
OPTION_PROFILES_RUST_TEST = "native_option_profiles"
OPTION_PROFILES_TRACE_BEGIN = "CRABC_MI_M7_OPTION_PROFILES_TRACE_BEGIN"
OPTION_PROFILES_TRACE_END = "CRABC_MI_M7_OPTION_PROFILES_TRACE_END"
# Environment images for descriptors read at process start or on a page
# allocation route; each runs one C and one Rust process.
OPTION_PROFILES = {
    "default": {},
    "disallow_arena_alloc": {"mimalloc_disallow_arena_alloc": "1"},
    "disallow_os_alloc": {"mimalloc_disallow_os_alloc": "1"},
    "disallow_both": {"mimalloc_disallow_arena_alloc": "1", "mimalloc_disallow_os_alloc": "1"},
    "reserve_os_memory": {"mimalloc_reserve_os_memory": "65536"},
    "arena_reserve": {"mimalloc_arena_reserve": "65536"},
    "arena_reserve_lazy": {"mimalloc_arena_reserve": "65536", "mimalloc_arena_eager_commit": "0"},
    "arena_reserve_eager": {"mimalloc_arena_reserve": "65536", "mimalloc_arena_eager_commit": "1"},
    # A lazily committed arena exposes the page commit decision.
    "page_commit_on_demand_0": {"mimalloc_page_commit_on_demand": "0", "mimalloc_arena_eager_commit": "0"},
    "page_commit_on_demand_1": {"mimalloc_page_commit_on_demand": "1", "mimalloc_arena_eager_commit": "0"},
    "page_commit_on_demand_2": {"mimalloc_page_commit_on_demand": "2", "mimalloc_arena_eager_commit": "0"},
    "arena_is_numa_local": {"mimalloc_arena_is_numa_local": "1"},
    "arena_is_numa_local_reserve": {"mimalloc_arena_is_numa_local": "1", "mimalloc_reserve_os_memory": "65536"},
    "allow_thp_0": {"mimalloc_allow_thp": "0"},
    "allow_large_os_pages": {"mimalloc_allow_large_os_pages": "1", "mimalloc_arena_reserve": "65536"},
    "reserve_huge_os_pages": {"mimalloc_reserve_huge_os_pages": "1"},
    "reserve_huge_os_pages_at": {"mimalloc_reserve_huge_os_pages": "1", "mimalloc_reserve_huge_os_pages_at": "0"},
    "max_vabits_40": {"mimalloc_max_vabits": "40"},
    "max_vabits_48": {"mimalloc_max_vabits": "48"},
    "pagemap_commit": {"mimalloc_pagemap_commit": "1"},
}
OPTION_PROFILE_CASES = ("small", "medium", "large", "huge")
OPTION_EFFECTS_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_option_effects_oracle.c"
OPTION_EFFECTS_RUST_TEST = "diagnostic_output::tests::source_option_effects_trace_for_pinned_c_comparison"
OPTION_EFFECTS_TRACE_BEGIN = "CRABC_MI_M7_OPTION_EFFECTS_TRACE_BEGIN"
OPTION_EFFECTS_TRACE_END = "CRABC_MI_M7_OPTION_EFFECTS_TRACE_END"
DESTROY_ON_EXIT_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_destroy_on_exit_oracle.c"
DESTROY_ON_EXIT_RUST_TESTS = (
    "runtime_lifecycle::destroy::tests::physical_destroy_transfers_live_worker_before_arena_and_page_map_release",
    "runtime_lifecycle::destroy::tests::physical_destroy_os_only_retains_source_pages_but_seals_all_native_access",
)
PAGE_MAX_CANDIDATES_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_page_max_candidates_driver.c"
PAGE_MAX_CANDIDATES_TRACE_BEGIN = "CRABC_MI_M7_PAGE_MAX_CANDIDATES_TRACE_BEGIN"
PAGE_MAX_CANDIDATES_TRACE_END = "CRABC_MI_M7_PAGE_MAX_CANDIDATES_TRACE_END"
# Every decision family both halves must trace; a family absent from both
# traces would otherwise compare equal.
OPTION_EFFECT_FAMILIES = (
    "host", "arena_max_object_size", "arena_purge_delay", "minimal_purge_size",
    "numa_node_count", "generic_collect", "arena_reserve", "purge",
)
RUST_TARGET = "x86_64-unknown-linux-musl"
BASELINE_ADAPTER = "crabc_mimalloc_native_mi_adapter"
BASELINE_PROBE = harness.ALLOCATOR_ROOT / "x86_64_m7_baseline_configuration.c"
BASELINE_RELEASE_PROFILE = {
    "opt_level": "3", "debuginfo": 0, "debug_assertions": False,
    "overflow_checks": False, "test": False,
}
# These two attributes belong to explicitly dispatched functions. Ordinary
# functions must retain the generic target CPU without an ISA feature list.
BASELINE_DISPATCH_FEATURES = {
    "+xsave",
    "+avx,+avx2,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+crc32,+ssse3",
}


def audit_default_baseline_artifact(build_output: str, target_dir: Path) -> dict[str, Any]:
    """Read the just-built static library and its compiler-emitted target IR."""

    records = [json.loads(line) for line in build_output.splitlines() if line.startswith('{')]
    artifacts = [entry for entry in records if entry.get("reason") == "compiler-artifact"
                 and entry.get("target", {}).get("name") == BASELINE_ADAPTER]
    if len(artifacts) != 1:
        raise harness.HarnessError("default baseline lacks one native adapter compiler artifact")
    entry = artifacts[0]
    if entry["target"].get("kind") != ["staticlib"] or entry.get("features") != []:
        raise harness.HarnessError("default baseline enabled an adapter feature or changed its artifact kind")
    if entry.get("profile") != BASELINE_RELEASE_PROFILE:
        raise harness.HarnessError("default baseline changed the release compiler profile")
    allocator = [record for record in records if record.get("reason") == "compiler-artifact"
                 and record.get("target", {}).get("name") == "crabc_mimalloc"]
    if len(allocator) != 1 or allocator[0].get("features") != [] \
            or allocator[0].get("profile") != BASELINE_RELEASE_PROFILE:
        raise harness.HarnessError("default baseline changed the allocator dependency profile")
    expected = target_dir / RUST_TARGET / "release/libcrabc_mimalloc_native_mi_adapter.a"
    if entry.get("filenames") != [str(expected)] or not expected.is_file():
        raise harness.HarnessError("default baseline did not build the expected native static library")
    if not expected.read_bytes().startswith(b"!<arch>\n"):
        raise harness.HarnessError("default baseline static library is not an archive")
    ir_files = list((target_dir / RUST_TARGET / "release/build/crabc-mimalloc-native-mi-adapter")
                    .glob("*/out/*.ll"))
    if len(ir_files) != 1:
        raise harness.HarnessError("default baseline lacks one compiler-emitted adapter IR image")
    ir = ir_files[0]
    emitted = ir.read_text()
    if emitted.count('target triple = "x86_64-unknown-linux-musl"') != 1:
        raise harness.HarnessError("default baseline changed the emitted Rust target triple")
    attributes = re.findall(r'^attributes #\d+ = \{[^\n]*\}$', emitted, re.MULTILINE)
    cpu_attributes = [line for line in attributes if '"target-cpu"=' in line]
    if not cpu_attributes or any('"target-cpu"="x86-64"' not in line for line in cpu_attributes):
        raise harness.HarnessError("default baseline raised the emitted default target CPU")
    feature_attributes = [re.search(r'"target-features"="([^"]+)"', line) for line in cpu_attributes]
    features = {match.group(1) for match in feature_attributes if match}
    if not any(match is None for match in feature_attributes) or not features <= BASELINE_DISPATCH_FEATURES:
        raise harness.HarnessError("default baseline changed the emitted ISA feature image")
    return {
        "artifact": harness.relative(expected),
        "artifact_sha256": hashlib.sha256(expected.read_bytes()).hexdigest(),
        "ir": harness.relative(ir),
        "ir_sha256": hashlib.sha256(ir.read_bytes()).hexdigest(),
        "target": RUST_TARGET, "target_cpu": "x86-64",
        "dispatch_features": sorted(features),
        "profile": dict(entry["profile"]), "features": list(entry["features"]),
    }


def audit_default_baseline_configuration(c_output: str, rust_output: str) -> str:
    """Compare the observable release image from the two built libraries."""

    lines = rust_output.splitlines()
    if len(lines) != 4 or lines[:3] != [
        "debug level : 0", "secure level: 0", "mem tracking: none",
    ] or not re.fullmatch(r"free: aligned, page size: [1-9][0-9]*", lines[3]):
        raise harness.HarnessError("default baseline has a non-release runtime configuration image")
    if c_output != rust_output:
        raise harness.HarnessError(f"default baseline pinned-C/Rust configuration differs: C={c_output!r}, Rust={rust_output!r}")
    return rust_output


def run_default_baseline_audit(offline: bool, scratch: Path) -> dict[str, Any]:
    """Build the default native artifact and compare its release image to pinned C."""

    harness.require_native_x86_64()
    scratch.mkdir(parents=True, exist_ok=True)
    target_dir = scratch / "cargo-target"
    build_command = [
        harness.require_tool("cargo"), "rustc", "--locked", "--release", "--target", RUST_TARGET,
        "-p", "crabc-mimalloc-native-mi-adapter", "--target-dir",
        str(target_dir), "--message-format=json", "--", "--emit=link,llvm-ir",
    ]
    build = harness.command_record(build_command, cwd=harness.ROOT,
                                   env=dict(os.environ), timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
    harness.require_success(build, "default native allocator artifact build")
    artifact = audit_default_baseline_artifact(str(build["stdout"]), target_dir)
    configuration_test_command = [
        harness.require_tool("cargo"), "test", "--locked", "--release", "--target", RUST_TARGET,
        "-p", "crabc-mimalloc", "--lib",
        "config::tests::selected_release_constants_match_the_pinned_linux_64_profiles",
        "--target-dir", str(target_dir), "--", "--exact",
    ]
    configuration_test = harness.command_record(
        configuration_test_command, cwd=harness.ROOT, env=dict(os.environ),
        timeout_seconds=EVIDENCE_TIMEOUT_SECONDS,
    )
    harness.require_success(configuration_test, "default release allocator configuration constants")
    if "running 1 test\n" not in str(configuration_test["stdout"]) \
            or "test result: ok. 1 passed; 0 failed;" not in str(configuration_test["stdout"]):
        raise harness.HarnessError("default release configuration check did not execute exactly one test")
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    source = harness.safe_extract(archive, scratch / "source", pin["archive_root"])
    compiler = harness.require_tool("musl-gcc")
    c_probe = scratch / "baseline-c"
    rust_probe = scratch / "baseline-rust"
    c_build = harness.command_record([
        compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
        *harness.CONFIGURATION_PROFILES["release"], "-I", str(source / "include"),
        str(BASELINE_PROBE), str(source / "src/static.c"), "-pthread", "-o", str(c_probe),
    ], cwd=source, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
    harness.require_success(c_build, "pinned C release configuration probe build")
    rust_build = harness.command_record([
        compiler, "-std=c11", "-O2", "-I", str(source / "include"),
        str(BASELINE_PROBE), str(target_dir / RUST_TARGET / "release/libcrabc_mimalloc_native_mi_adapter.a"),
        "-pthread", "-o", str(rust_probe),
    ], cwd=source, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
    harness.require_success(rust_build, "Rust release configuration probe link")
    c_run = harness.command_record([str(c_probe)], cwd=scratch, env={}, timeout_seconds=60)
    rust_run = harness.command_record([str(rust_probe)], cwd=scratch, env={}, timeout_seconds=60)
    harness.require_success(c_run, "pinned C release configuration probe")
    harness.require_success(rust_run, "Rust release configuration probe")
    configuration = audit_default_baseline_configuration(str(c_run["stdout"]), str(rust_run["stdout"]))
    report = {"artifact": artifact, "build_command": build_command,
              "configuration_test_command": configuration_test_command,
              "configuration_test_output": str(configuration_test["stdout"]),
              "c_configuration": str(c_run["stdout"]), "rust_configuration": configuration,
              "c_release_flags": list(harness.CONFIGURATION_PROFILES["release"]),
              "pinned_archive": harness.relative(archive)}
    harness.write_json(scratch / "default-baseline.json", report)
    return report


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


def destroy_on_exit_fields(output: str, prefix: str, description: str) -> list[int]:
    """Read the seven ordered physical ownership observations."""

    rows = re.findall(rf"^{re.escape(prefix)}\.(\d+)=(\d+)$", output, re.MULTILINE)
    if [int(index) for index, _ in rows] != list(range(7)):
        raise harness.HarnessError(f"{description} lacks seven ordered process-done fields")
    return [int(value) for _, value in rows]


def run_destroy_on_exit_differential(offline: bool) -> dict[str, Any]:
    """Compare physical process-done ownership after a preallocation option set."""

    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory("crabc-mimalloc-x86_64-m7-destroy-on-exit-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        binary = temporary / "destroy-on-exit-c"
        c_build = harness.command_record([
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
            "-DMI_PRIM_HAS_PROCESS_ATTACH=1", "-I", str(source / "include"),
            "-I", str(source / "src"), *harness.CONFIGURATION_PROFILES["release"],
            str(DESTROY_ON_EXIT_ORACLE), "-pthread", "-o", str(binary),
        ], cwd=source, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
        harness.require_success(c_build, "pinned C destroy-on-exit build")
        result: dict[str, Any] = {"c_build_command": c_build["command"], "modes": {}}
        for mode, test in enumerate(DESTROY_ON_EXIT_RUST_TESTS):
            c_run = harness.command_record([str(binary), str(mode)], cwd=source, env={}, timeout_seconds=60)
            harness.require_success(c_run, f"pinned C destroy-on-exit mode {mode}")
            rust_run = rust_trace(test, f"destroy-on-exit-{mode}")
            c_fields = destroy_on_exit_fields(str(c_run["stdout"]), "destroy_on_exit", f"C mode {mode}")
            if str(c_run["stdout"]).splitlines() != [
                f"destroy_on_exit.{index}={value}" for index, value in enumerate(c_fields)
            ]:
                raise harness.HarnessError(f"destroy-on-exit mode {mode} emitted unexpected C output")
            rust_output = re.sub(
                rf"^test {re.escape(test)} \.\.\. (?=m2\.process\.destroy\.0=)", "",
                str(rust_run["stdout"]), count=1, flags=re.MULTILINE,
            )
            rust_fields = destroy_on_exit_fields(rust_output, "m2.process.destroy", f"Rust mode {mode}")
            if c_fields != rust_fields:
                raise harness.HarnessError(f"destroy-on-exit mode {mode} C/Rust ownership differs: {c_fields} != {rust_fields}")
            if c_fields[0] != 2 or c_fields[1] != 1 or c_fields[2] != mode or c_fields[3:] != [0, 1, 0, 1]:
                raise harness.HarnessError(f"destroy-on-exit mode {mode} lacks the source page/arena disposition")
            if str(c_run["stderr"]).strip() or "mimalloc:" in str(rust_run["stdout"]):
                raise harness.HarnessError(f"destroy-on-exit mode {mode} changed the quiet final-output state")
            result["modes"][str(mode)] = {
                "c_command": c_run["command"], "rust_command": rust_run["command"],
                "c_exit_status": c_run["status"], "rust_exit_status": rust_run["status"],
                "c_stderr": c_run["stderr"], "rust_stdout": rust_run["stdout"],
                "fields": c_fields,
            }
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    harness.write_json(ARTIFACTS / "destroy-on-exit.json", result)
    return result


def require_page_max_candidates_choice(trace: Mapping[str, str], limit: int, description: str) -> None:
    """Require a changed page choice with both live block patterns preserved."""

    expected = "first" if limit == 0 else "transferred"
    if trace != {
        "case.limit": str(limit), "case.distinct_pages": "1", "case.selected": expected,
        "case.first_data": "1", "case.transferred_data": "1", "case.usable": "8192",
    }:
        raise harness.HarnessError(f"{description} did not select {expected} with intact live data: {trace}")


def run_page_max_candidates_differential(offline: bool) -> dict[str, Any]:
    """Build one public driver against pinned C and the native Rust adapter."""

    import x86_64_m4_gate as m4

    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory("crabc-mimalloc-x86_64-m7-page-max-candidates-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "page-max-candidates-c"
        c_build = harness.command_record([
            compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
            "-DCRABC_PINNED_C=1", *harness.CONFIGURATION_PROFILES["release"],
            "-I", str(source / "include"), "-I", str(source / "src"),
            str(PAGE_MAX_CANDIDATES_DRIVER), "-pthread", "-o", str(c_driver),
        ], cwd=source, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
        harness.require_success(c_build, "pinned C page-max-candidates driver build")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "page-max-candidates-rust"
        rust_build = harness.command_record([
            compiler, "-std=c11", "-O2", "-I", str(source / "include"),
            str(PAGE_MAX_CANDIDATES_DRIVER), str(library), "-pthread", "-o", str(rust_driver),
        ], cwd=source, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
        harness.require_success(rust_build, "Rust page-max-candidates driver link")
        report: dict[str, Any] = {"c_build_command": c_build["command"],
                                  "rust_build_command": rust_build["command"], "modes": {}}
        for limit in (0, 4):
            executions = {
                side: harness.command_record([str(binary), str(limit)], cwd=temporary, env={}, timeout_seconds=60)
                for side, binary in (("c", c_driver), ("rust", rust_driver))
            }
            for side, execution in executions.items():
                harness.require_success(execution, f"{side} page-max-candidates limit {limit}")
            c_trace = parse_options_trace(str(executions["c"]["stdout"]), f"C limit {limit}",
                                          PAGE_MAX_CANDIDATES_TRACE_BEGIN, PAGE_MAX_CANDIDATES_TRACE_END)
            rust_trace_image = parse_options_trace(str(executions["rust"]["stdout"]), f"Rust limit {limit}",
                                                   PAGE_MAX_CANDIDATES_TRACE_BEGIN, PAGE_MAX_CANDIDATES_TRACE_END)
            source_queue = c_trace.pop("source.queue", None)
            if source_queue != "2,1,8,1,2,8,1,1":
                raise harness.HarnessError(f"C limit {limit} lacks the two expandable source candidates: {source_queue}")
            require_page_max_candidates_choice(c_trace, limit, f"C limit {limit}")
            require_page_max_candidates_choice(rust_trace_image, limit, f"Rust limit {limit}")
            compare_options_traces(c_trace, rust_trace_image)
            report["modes"][str(limit)] = {
                "c_command": executions["c"]["command"], "rust_command": executions["rust"]["command"],
                "source_queue": source_queue, "trace": dict(sorted(c_trace.items())),
            }
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    harness.write_json(ARTIFACTS / "page-max-candidates.json", report)
    return report


def require_complete_error_sites_trace(trace: Mapping[str, str], description: str) -> None:
    """Reject a trace that omits a request or one of its three records."""

    if "error_site.startup.messages" not in trace:
        raise harness.HarnessError(f"{description} lacks error_site.startup.messages")
    for case in ERROR_SITE_CASES:
        for suffix in ("messages", "deferred", "null", "errno"):
            if f"error_site.{case}.{suffix}" not in trace:
                raise harness.HarnessError(f"{description} lacks error_site.{case}.{suffix}")


def require_complete_option_profile_trace(trace: Mapping[str, str], description: str) -> None:
    """Reject a profile trace that omits a request record or the first arena."""

    for key in ("profile.first_arena", "profile.page_map", "profile.arena_count", "profile.thp_enabled"):
        if key not in trace:
            raise harness.HarnessError(f"{description} lacks {key}")
    for case in OPTION_PROFILE_CASES:
        for suffix in ("null", "memkind", "slice_pcommitted"):
            if f"profile.{case}.{suffix}" not in trace:
                raise harness.HarnessError(f"{description} lacks profile.{case}.{suffix}")


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
    compile_defines: Sequence[str] = (),
) -> dict[str, Any]:
    """Build and run one pinned-C probe against the release configuration."""

    binary = temporary / f"m7-{subject}-c"
    build = harness.command_record(
        [
            harness.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            "-DMI_LIBC_MUSL=1", "-I", str(source / "include"), "-I", str(source / "src"),
            *harness.CONFIGURATION_PROFILES["release"], *compile_defines,
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
    rust_features: Sequence[str] = (),
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
        "-p", "crabc-mimalloc", "--no-default-features",
        *(["--features", ",".join(rust_features)] if rust_features else []),
        *selection, "--nocapture", "--test-threads=1",
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
    environment: Mapping[str, str] | None = None, c_stderr_record: tuple[str, Any] | None = None,
    compile_defines: Sequence[str] = (), rust_features: Sequence[str] = (),
) -> dict[str, Any]:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory(f"crabc-mimalloc-x86_64-m7-{subject}-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        c_execution = c_oracle_trace(oracle, subject, source, temporary, environment, compile_defines)
    rust_execution = rust_trace(
        test, subject, integration_test=integration_test, environment=environment,
        rust_features=rust_features,
    )
    c_trace = parse_options_trace(str(c_execution["stdout"]), f"pinned C {subject} trace", begin, end)
    if c_stderr_record is not None:
        key, derive = c_stderr_record
        if key in c_trace:
            raise harness.HarnessError(f"pinned C {subject} trace repeated trace key {key}")
        c_trace[key] = derive(str(c_execution["stderr"]))
    rust_trace_image = parse_options_trace(str(rust_execution["stdout"]), f"Rust {subject} trace", begin, end)
    if require_complete is not None:
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


def run_optional_isa_differential(offline: bool) -> dict[str, Any]:
    """Compare source-built bitmap claims under scalar, arch, and AVX2 selection."""

    harness.require_native_x86_64()
    flag_rows = re.findall(r"^flags\s*:\s*(.*)$", Path("/proc/cpuinfo").read_text(), re.MULTILINE)
    if not flag_rows:
        raise harness.HarnessError("optional ISA unavailable: CPU feature rows are absent")
    flags = set.intersection(*(set(row.split()) for row in flag_rows))
    # `target-cpu=haswell` enables these compiler features; Linux names
    # `sse3` as `pni`, `lzcnt` as `abm`, and `cmpxchg16b` as `cx16`.
    required = {
        "abm", "aes", "avx", "avx2", "bmi1", "bmi2", "cx16", "erms",
        "f16c", "fma", "fxsr", "lahf_lm", "movbe", "pclmulqdq", "pni",
        "popcnt", "rdrand", "sse", "sse2", "sse4_1", "sse4_2", "ssse3",
        "xsave", "xsaveopt",
    }
    if not required <= flags:
        raise harness.HarnessError(f"optional ISA unavailable: CPU lacks {sorted(required - flags)}")
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    compiler = harness.require_tool("musl-gcc")
    objdump = harness.require_tool("objdump")
    modes = {
        "scalar": ([], [], ""),
        "no_opt_arch": (["-DMI_NO_OPT_ARCH=1", "-DMI_OPT_SIMD=0"], [], ""),
        "opt_arch": (["-march=haswell", "-mavx2", "-DMI_OPT_SIMD=0"], [], "-C target-cpu=haswell"),
        "opt_simd": (["-march=haswell", "-mavx2", "-DMI_OPT_SIMD=1"], ["mi-opt-simd"], "-C target-cpu=haswell"),
    }
    profiles: dict[str, Any] = {}
    with harness.temporary_directory("crabc-mimalloc-x86_64-m7-optional-isa-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        for mode, (c_flags, features, rustflags) in modes.items():
            c_binary = temporary / f"{mode}-c"
            c_build = harness.command_record([
                compiler, "-std=c11", "-O2", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                *harness.CONFIGURATION_PROFILES["release"], *c_flags,
                "-I", str(source / "include"), "-I", str(source / "src"),
                str(OPTIONAL_ISA_ORACLE), "-pthread", "-o", str(c_binary),
            ], cwd=source, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
            harness.require_success(c_build, f"optional ISA {mode} C build")
            c_run = harness.command_record([str(c_binary)], cwd=source, env={})
            harness.require_success(c_run, f"optional ISA {mode} C trace")
            target = temporary / "cargo-target"
            rust_build = harness.command_record([
                harness.require_tool("cargo"), "test", "--locked", "--target", RUST_TARGET,
                "-p", "crabc-mimalloc", "--no-default-features",
                *(["--features", ",".join(features)] if features else []),
                "--lib", "--no-run", "--message-format=json", "--target-dir", str(target),
            ], cwd=harness.ROOT, env={**os.environ, "RUSTFLAGS": rustflags},
                timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
            harness.require_success(rust_build, f"optional ISA {mode} Rust build")
            artifacts = [json.loads(line) for line in str(rust_build["stdout"]).splitlines()
                         if line.startswith("{") and json.loads(line).get("reason") == "compiler-artifact"
                         and json.loads(line).get("target", {}).get("name") == "crabc_mimalloc"
                         and json.loads(line).get("executable")]
            if len(artifacts) != 1:
                raise harness.HarnessError(f"optional ISA {mode} lacks one Rust unit executable")
            rust_binary = Path(artifacts[0]["executable"])
            rust_run = harness.command_record([
                str(rust_binary), "bitmap::native_tests::optional_isa_bitmap_allocation_trace",
                "--exact", "--nocapture", "--test-threads=1",
            ], cwd=harness.ROOT)
            harness.require_success(rust_run, f"optional ISA {mode} Rust trace")
            if harness.parse_rust_test_count(str(rust_run["stdout"]) + str(rust_run["stderr"])) != 1:
                raise harness.HarnessError(f"optional ISA {mode} ran the wrong Rust test inventory")
            retry_command = None
            if mode == "opt_simd":
                retry_command = [str(rust_binary),
                                 "bitmap::native_tests::optional_isa_retries_stale_vector_candidates",
                                 "--exact", "--test-threads=1"]
                retry_run = harness.command_record(retry_command, cwd=harness.ROOT)
                harness.require_success(retry_run, "optional ISA stale-vector retry regression")
                if harness.parse_rust_test_count(str(retry_run["stdout"]) + str(retry_run["stderr"])) != 1:
                    raise harness.HarnessError("optional ISA stale-vector retry test did not execute")
            c_trace = parse_options_trace(str(c_run["stdout"]), f"{mode} C", OPTIONAL_ISA_TRACE_BEGIN, OPTIONAL_ISA_TRACE_END)
            rust_trace_image = parse_options_trace(str(rust_run["stdout"]), f"{mode} Rust", OPTIONAL_ISA_TRACE_BEGIN, OPTIONAL_ISA_TRACE_END)
            expected = {"bitmap.bits", "bitmap.arch", "bitmap.path", "one.first", "one.second", "one.third", "byte.first", "byte.second", "byte.temporary", "bin.one", "bin.byte"}
            expected |= {f"{stage}.{suffix}" for stage in ("empty", "one_drained", "byte_drained", "full")
                         for suffix in ("clear", "set", *(f"field{i}" for i in range(8)))}
            if set(c_trace) != expected or set(rust_trace_image) != expected:
                raise harness.HarnessError(f"optional ISA {mode} trace omitted bitmap state")
            required_values = {
                "bitmap.bits": "512", "one.first": "0", "one.second": "256", "one.third": "448",
                "byte.first": "80", "byte.second": "432", "byte.temporary": "0",
                "bin.one": "0", "bin.byte": "8",
                "empty.clear": "1", "empty.set": "0",
                "one_drained.clear": "1", "one_drained.set": "0",
                "byte_drained.clear": "1", "byte_drained.set": "0",
                "full.clear": "0", "full.set": "1",
            }
            if any(c_trace[key] != value for key, value in required_values.items()):
                raise harness.HarnessError(f"optional ISA {mode} lost a source bitmap selection boundary")
            arch = "avx2" if mode in ("opt_arch", "opt_simd") else "scalar"
            path = "avx2" if mode == "opt_simd" else "scalar"
            if c_trace["bitmap.arch"] != arch or c_trace["bitmap.path"] != path:
                raise harness.HarnessError(f"optional ISA {mode} selected the wrong C bitmap branch")
            compare_options_traces(c_trace, rust_trace_image)
            c_disassembly = harness.command_record([objdump, "-d", str(c_binary)], cwd=source)
            rust_disassembly = harness.command_record([objdump, "-Cd", str(rust_binary)], cwd=source)
            harness.require_success(c_disassembly, f"optional ISA {mode} C disassembly")
            harness.require_success(rust_disassembly, f"optional ISA {mode} Rust disassembly")
            vector_opcodes = ("vpcmpeqq", "vpcmpeqb", "vpmovmskb")
            c_counts = {opcode: len(re.findall(rf"\b{opcode}\b", str(c_disassembly["stdout"])))
                        for opcode in vector_opcodes}
            rust_counts = {opcode: len(re.findall(rf"\b{opcode}\b", str(rust_disassembly["stdout"])))
                           for opcode in vector_opcodes}
            c_has_opcodes = all(c_counts.values())
            rust_has_opcodes = all(rust_counts.values())
            if mode == "opt_simd" and (not c_has_opcodes or not rust_has_opcodes):
                raise harness.HarnessError("optional ISA AVX2 bitmap instruction selection absent")
            profiles[mode] = {"c_trace": c_trace, "rust_trace": rust_trace_image,
                              "c_build_command": c_build["command"], "rust_build_command": rust_build["command"],
                              "c_binary_has_avx2_bitmap_opcodes": c_has_opcodes,
                              "rust_binary_has_avx2_bitmap_opcodes": rust_has_opcodes,
                              "bitmap_selected_path": path,
                              "c_opcode_counts": c_counts, "rust_opcode_counts": rust_counts,
                              "rust_features": features, "rustflags": rustflags,
                              "retry_test_command": retry_command}
        source_files = harness.source_file_records(source, ("src/bitmap.c", "src/bitmap.h", "src/static.c"))
    scalar = {key: value for key, value in profiles["scalar"]["c_trace"].items()
              if key not in ("bitmap.arch", "bitmap.path")}
    if any({key: value for key, value in profile["c_trace"].items()
            if key not in ("bitmap.arch", "bitmap.path")} != scalar for profile in profiles.values()):
        raise harness.HarnessError("optional ISA changed sequential bitmap allocation semantics")
    report = {"status": "passed", "cpu_flags": sorted(required), "cpu_count": len(flag_rows),
              "profiles": profiles,
              "compared_key_count": len(scalar) + 2, "source_tag": pin["tag"],
              "source_files": source_files,
              "fixture_sha256": hashlib.sha256(OPTIONAL_ISA_ORACLE.read_bytes()).hexdigest(),
              "bitmap_sha256": hashlib.sha256((harness.ROOT / "crabc-mimalloc/src/bitmap.rs").read_bytes()).hexdigest()}
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    harness.write_json(ARTIFACTS / "optional-isa.json", report)
    return report


def run_options_differential(offline: bool) -> dict[str, Any]:
    return run_trace_differential(
        offline, subject="options", oracle=OPTIONS_ORACLE, test=OPTIONS_RUST_TEST,
        begin=OPTIONS_TRACE_BEGIN, end=OPTIONS_TRACE_END,
        require_complete=require_complete_options_trace, report_name="options-environment.json",
    )


def run_delayed_output_saturation_differential(offline: bool) -> dict[str, Any]:
    return run_trace_differential(
        offline, subject="delayed-output-saturation", oracle=DELAYED_OUTPUT_SATURATION_ORACLE,
        test=DELAYED_OUTPUT_SATURATION_TEST, begin=DELAYED_OUTPUT_SATURATION_TRACE_BEGIN,
        end=DELAYED_OUTPUT_SATURATION_TRACE_END,
        require_complete=None,
        report_name="delayed-output-saturation.json",
    )


def run_show_errors_profile_differential(offline: bool) -> dict[str, Any]:
    return run_trace_differential(
        offline, subject="show-errors-profile", oracle=OPTIONS_ORACLE, test=OPTIONS_RUST_TEST,
        begin=OPTIONS_TRACE_BEGIN, end=OPTIONS_TRACE_END,
        require_complete=require_complete_options_trace, report_name="show-errors-profile.json",
        compile_defines=("-DMI_SHOW_ERRORS=1",), rust_features=("mi-show-errors",),
    )


def startup_record_from_stderr(stderr: str) -> str:
    """The pinned C probe's startup output, as the Rust `startup` record.

    Startup reports reach the delayed buffer before any registration, and
    `_mi_options_post_init` flushes it to stderr as one fragment, which is
    what the Rust half's default primitive receives at the same point.
    """

    if not stderr:
        return ""
    return re.sub(r"thread 0x[0-9A-F]+: ", "thread 0xTID: ", stderr).encode("ascii").hex()


ADAPTER_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_adapter_driver.c"
ADAPTER_TRACE_BEGIN = "CRABC_MI_M7_ADAPTER_TRACE_BEGIN"
ADAPTER_TRACE_END = "CRABC_MI_M7_ADAPTER_TRACE_END"


THREAD_INIT_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_thread_init_driver.c"
THREAD_INIT_TRACE_BEGIN = "CRABC_MI_M7_THREAD_INIT_TRACE_BEGIN"
THREAD_INIT_TRACE_END = "CRABC_MI_M7_THREAD_INIT_TRACE_END"
PAGE_MAP_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_page_map_driver.c"
PAGE_MAP_TRACE_BEGIN = "CRABC_MI_M7_PAGE_MAP_TRACE_BEGIN"
PAGE_MAP_TRACE_END = "CRABC_MI_M7_PAGE_MAP_TRACE_END"
STATISTICS_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_driver.c"
STATISTICS_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_TRACE_BEGIN"
STATISTICS_TRACE_END = "CRABC_MI_M7_STATISTICS_TRACE_END"
STATISTICS_LEVEL_ONE_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_level_one_driver.c"
STATISTICS_LEVEL_ONE_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_LEVEL_ONE_TRACE_BEGIN"
STATISTICS_LEVEL_ONE_TRACE_END = "CRABC_MI_M7_STATISTICS_LEVEL_ONE_TRACE_END"
STATISTICS_LEVEL_ONE_OUTPUT_MERGE_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_level_one_output_merge_oracle.c"
STATISTICS_LEVEL_ONE_OUTPUT_MERGE_TEST = "diagnostic_output::tests::level_one_output_merge_trace_for_pinned_c_comparison"
STATISTICS_LEVEL_ONE_OUTPUT_MERGE_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_LEVEL_ONE_OUTPUT_MERGE_TRACE_BEGIN"
STATISTICS_LEVEL_ONE_OUTPUT_MERGE_TRACE_END = "CRABC_MI_M7_STATISTICS_LEVEL_ONE_OUTPUT_MERGE_TRACE_END"
STATISTICS_LEVEL_TWO_REQUESTED_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_level_two_requested_oracle.c"
STATISTICS_LEVEL_TWO_REQUESTED_TEST = "diagnostic_output::tests::level_two_requested_trace_for_pinned_c_comparison"
STATISTICS_LEVEL_TWO_REQUESTED_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_LEVEL_TWO_REQUESTED_TRACE_BEGIN"
STATISTICS_LEVEL_TWO_REQUESTED_TRACE_END = "CRABC_MI_M7_STATISTICS_LEVEL_TWO_REQUESTED_TRACE_END"
STATISTICS_LEVEL_TWO_BINS_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_level_two_bins_oracle.c"
STATISTICS_LEVEL_TWO_BINS_TEST = "diagnostic_output::tests::level_two_bins_trace_for_pinned_c_comparison"
STATISTICS_LEVEL_TWO_BINS_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_LEVEL_TWO_BINS_TRACE_BEGIN"
STATISTICS_LEVEL_TWO_BINS_TRACE_END = "CRABC_MI_M7_STATISTICS_LEVEL_TWO_BINS_TRACE_END"
STATISTICS_LEVEL_TWO_PAGE_HUGE_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_level_two_page_huge_oracle.c"
STATISTICS_LEVEL_TWO_PAGE_HUGE_TEST = "diagnostic_output::tests::level_two_page_huge_trace_for_pinned_c_comparison"
STATISTICS_LEVEL_TWO_PAGE_HUGE_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_LEVEL_TWO_PAGE_HUGE_TRACE_BEGIN"
STATISTICS_LEVEL_TWO_PAGE_HUGE_TRACE_END = "CRABC_MI_M7_STATISTICS_LEVEL_TWO_PAGE_HUGE_TRACE_END"
STATISTICS_JSON_ORACLE = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_json_oracle.c"
STATISTICS_JSON_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_JSON_TRACE_BEGIN"
STATISTICS_JSON_TRACE_END = "CRABC_MI_M7_STATISTICS_JSON_TRACE_END"
STATISTICS_PAGE_EXTEND_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_page_extend_driver.c"
STATISTICS_PAGE_EXTEND_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_PAGE_EXTEND_TRACE_BEGIN"
STATISTICS_PAGE_EXTEND_TRACE_END = "CRABC_MI_M7_STATISTICS_PAGE_EXTEND_TRACE_END"
STATISTICS_PAGE_SECOND_EXTENSION_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_page_second_extension_driver.c"
STATISTICS_PAGE_SECOND_EXTENSION_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_PAGE_SECOND_EXTENSION_TRACE_BEGIN"
STATISTICS_PAGE_SECOND_EXTENSION_TRACE_END = "CRABC_MI_M7_STATISTICS_PAGE_SECOND_EXTENSION_TRACE_END"
STATISTICS_HUGE_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_huge_driver.c"
STATISTICS_HUGE_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_HUGE_TRACE_BEGIN"
STATISTICS_HUGE_TRACE_END = "CRABC_MI_M7_STATISTICS_HUGE_TRACE_END"
STATISTICS_HUGE_PAGE_BIN_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_huge_page_bin_driver.c"
STATISTICS_HUGE_PAGE_BIN_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_HUGE_PAGE_BIN_TRACE_BEGIN"
STATISTICS_HUGE_PAGE_BIN_TRACE_END = "CRABC_MI_M7_STATISTICS_HUGE_PAGE_BIN_TRACE_END"
STATISTICS_REMOTE_NORMAL_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_remote_normal_driver.c"
STATISTICS_REMOTE_NORMAL_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_REMOTE_NORMAL_TRACE_BEGIN"
STATISTICS_REMOTE_NORMAL_TRACE_END = "CRABC_MI_M7_STATISTICS_REMOTE_NORMAL_TRACE_END"
STATISTICS_ALIGNED_HUGE_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_aligned_huge_driver.c"
STATISTICS_ALIGNED_HUGE_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_ALIGNED_HUGE_TRACE_BEGIN"
STATISTICS_ALIGNED_HUGE_TRACE_END = "CRABC_MI_M7_STATISTICS_ALIGNED_HUGE_TRACE_END"
STATISTICS_REQUESTED_PRODUCTION_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_requested_production_driver.c"
STATISTICS_REQUESTED_PRODUCTION_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_REQUESTED_PRODUCTION_TRACE_BEGIN"
STATISTICS_REQUESTED_PRODUCTION_TRACE_END = "CRABC_MI_M7_STATISTICS_REQUESTED_PRODUCTION_TRACE_END"
STATISTICS_FAST_ALLOCATION_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_fast_allocation_driver.c"
STATISTICS_FAST_ALLOCATION_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_FAST_ALLOCATION_TRACE_BEGIN"
STATISTICS_FAST_ALLOCATION_TRACE_END = "CRABC_MI_M7_STATISTICS_FAST_ALLOCATION_TRACE_END"
STATISTICS_REMOTE_BIN_DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_remote_bin_driver.c"
STATISTICS_REMOTE_BIN_TRACE_BEGIN = "CRABC_MI_M7_STATISTICS_REMOTE_BIN_TRACE_BEGIN"
STATISTICS_REMOTE_BIN_TRACE_END = "CRABC_MI_M7_STATISTICS_REMOTE_BIN_TRACE_END"


def require_statistics_huge_page_bin(
    trace: Mapping[str, str], description: str, *, fresh_worker: bool = False,
) -> None:
    """Require huge page-bin release and the selected worker's process image."""

    expected = {
        "profile.level": "2", "request": "524289", "usable": "589824",
        "disallow_os_alloc": "1", "disallow_arena_alloc": "0",
        "allocated.mapped": "1", "worker.mapped": "-1" if fresh_worker else "1",
        "worker.fresh": "1" if fresh_worker else "0",
        "worker.followup_usable": "0",
        "before.arena": trace.get("before.arena"),
        "allocated.arena": trace.get("allocated.arena"),
        "terminal.arena": trace.get("terminal.arena"),
    }
    stages = {
        "allocated": ("589824,589824,589824", "0,0,0", "0,0,0", "0,0,0",
                      "1,1,1", "1,1,1", "1", "0"),
        "merged": ("589824,589824,589824", "0,0,0", "0,0,0", "0,0,0",
                   "1,1,1", "1,1,1", "1", "0"),
        "freed": ("589824,589824,0", "8,8,8", "8,8,0", "0,0,0",
                  "1,1,0", "2,1,0", "1", "1"),
        "terminal": ("589824,589824,0", "8,8,8", "8,8,0", "0,0,0",
                     "1,1,0", "2,1,0", "1", "1"),
    }
    if fresh_worker:
        fresh_stage = (
            "589824,589824,589824", "0,0,0", "0,0,0", "0,0,0",
            "1,1,0", "1,1,0", "1", "0",
        )
        stages["freed"] = fresh_stage
        stages["terminal"] = fresh_stage
    fields = ("huge", "requested", "normal", "huge_bin", "huge_page_bin", "pages",
              "huge_count", "normal_count")
    for stage, values in stages.items():
        expected.update({f"{stage}.{field}": value for field, value in zip(fields, values)})
    if dict(trace) != expected:
        raise harness.HarnessError(f"{description} lost huge singleton or worker merge statistics: {trace}")
    try:
        arena_before = [int(value) for value in trace["before.arena"].split(",")]
        arena_allocated = [int(value) for value in trace["allocated.arena"].split(",")]
        arena_terminal = [int(value) for value in trace["terminal.arena"].split(",")]
    except ValueError as error:
        raise harness.HarnessError(f"{description} has invalid arena statistics") from error
    if (len(arena_before) != 3 or arena_before[0] <= 0 or arena_before[1] <= 0
            or arena_before[2] < 1 or arena_allocated != arena_before
            or arena_terminal != arena_before):
        raise harness.HarnessError(f"{description} lost the arena-only huge singleton: {trace}")


def require_statistics_remote_bin(trace: Mapping[str, str], description: str) -> None:
    """Require the freeing Theap's negative bin current before its merge."""

    expected = {
        "profile.level": "2", "warm.usable": "64", "target.usable": "64", "target.bin": "8",
        "allocated.bin": "1,1,1", "allocated.requested": "64,64,64",
        "allocated.normal": "64,64,64", "allocated.normal_count": "1",
        "main_merged.bin": "1,1,1", "main_merged.requested": "64,64,64",
        "main_merged.normal": "64,64,64", "main_merged.normal_count": "1",
        "freed.bin": "2,2,0", "freed.requested": "128,128,128",
        "freed.normal": "128,128,0", "freed.normal_count": "2",
        "worker.bin.hex": trace.get("worker.bin.hex"),
        "worker.requested.hex": trace.get("worker.requested.hex"),
        "medium.warm.usable": "32768", "medium.target.usable": "32768",
        "medium.target.bin": "44", "medium.disallow_os_alloc": "1",
        "medium.disallow_arena_alloc": "0", "medium.target.mapped": "1",
        "medium.survivor.mapped": "1", "medium.survivor.data": "1",
        "medium.before.arena": trace.get("medium.before.arena"),
        "medium.allocated.arena": trace.get("medium.allocated.arena"),
        "medium.terminal.arena": trace.get("medium.terminal.arena"),
        "medium.allocated.bin": "2,2,2", "medium.allocated.requested": "65536,65536,65536",
        "medium.allocated.normal": "65536,65408,65536", "medium.allocated.normal_count": "2",
        "medium.allocated.page_bin": "1,1,1",
        "medium.merged.bin": "2,2,2", "medium.merged.requested": "65536,65536,65536",
        "medium.merged.normal": "65536,65408,65536", "medium.merged.normal_count": "2",
        "medium.merged.page_bin": "1,1,1",
        "medium.freed.bin": "3,3,1", "medium.freed.requested": "98304,98304,98304",
        "medium.freed.normal": "98304,98176,32768", "medium.freed.normal_count": "3",
        "medium.freed.page_bin": "2,2,1",
        "medium.collected.bin": "3,3,1", "medium.collected.requested": "98304,98304,98304",
        "medium.collected.normal": "98304,98176,32768", "medium.collected.normal_count": "3",
        "medium.collected.page_bin": "2,2,1",
        "medium.terminal.bin": "3,3,0", "medium.terminal.requested": "98304,98304,98304",
        "medium.terminal.normal": "98304,98176,0", "medium.terminal.normal_count": "3",
        "medium.terminal.page_bin": "2,2,0",
        "worker.medium.bin.hex": trace.get("worker.medium.bin.hex"),
        "worker.medium.requested.hex": trace.get("worker.medium.requested.hex"),
    }
    if dict(trace) != expected:
        raise harness.HarnessError(f"{description} lost the remote bin merge or requested-size record: {trace}")
    try:
        arena_before = [int(value) for value in trace["medium.before.arena"].split(",")]
        arena_allocated = [int(value) for value in trace["medium.allocated.arena"].split(",")]
        arena_terminal = [int(value) for value in trace["medium.terminal.arena"].split(",")]
        bin_row = bytes.fromhex(trace["worker.bin.hex"]).decode("ascii")
        requested_row = bytes.fromhex(trace["worker.requested.hex"]).decode("ascii")
        medium_bin_row = bytes.fromhex(trace["worker.medium.bin.hex"]).decode("ascii")
        medium_requested_row = bytes.fromhex(trace["worker.medium.requested.hex"]).decode("ascii")
    except (ValueError, UnicodeDecodeError) as error:
        raise harness.HarnessError(f"{description} has invalid worker statistics text") from error
    if (len(arena_before) != 3 or arena_before[0] <= 0 or arena_before[1] <= 0
            or arena_before[2] < 1 or arena_allocated != arena_before
            or arena_terminal != arena_before):
        raise harness.HarnessError(f"{description} lost arena-only medium-page allocation: {trace}")
    if (bin_row.split() != ["bin", "S", "8:", "64", "B", "64", "B", "-64", "B",
                             "64", "B", "1", "not", "all", "freed"]
            or requested_row.split() != ["malloc", "req:", "64", "B"]
            or medium_bin_row.split() != ["bin", "M", "44:", "32.1", "KiB", "32.1", "KiB",
                                          "-32.1", "KiB", "32.1", "KiB", "1", "not", "all", "freed"]
            or medium_requested_row.split() != ["malloc", "req:", "32.1", "KiB"]):
        raise harness.HarnessError(f"{description} lost the freeing Theap's bin/requested rows: {trace}")


def require_statistics_fast_allocation(trace: Mapping[str, str], description: str) -> None:
    """Require every normal-bin boundary and its complete local lifetime."""

    try:
        level = int(trace["profile.level"])
    except (KeyError, ValueError) as error:
        raise harness.HarnessError(f"{description} lacks a statistics profile") from error
    if level not in (0, 1, 2):
        raise harness.HarnessError(f"{description} has an unsupported statistics profile")
    sizes = [word * 8 for word in range(1, 9)]
    base = 64
    while base < 512 * 1024:
        sizes.extend(base * quarter // 4 for quarter in range(5, 9))
        base *= 2
    geometry = {f"geometry.bin{index}": str(size) for index, size in enumerate(sizes, 1)}
    cases = {f"subword{request}": request for request in range(8)}
    previous = 0
    for index, size in enumerate(sizes, 1):
        cases.update({f"bin{index}.lower": previous + 1,
                      f"bin{index}.middle": previous + (size - previous) // 2 + 1,
                      f"bin{index}.upper": size})
        previous = size
    stages = ("prepared", "allocated", "merged", "reset", "freed", "final_merged", "terminal")
    stage_fields = ("normal", "huge", "requested", "bin", "normal_count",
                    "page_bin_current", "searches", "extensions")
    case_fields = ("request", "usable", "bin_index", "zero_all", "distinct")
    expected = {"profile.level", *geometry,
                *(f"{case}.{field}" for case in cases for field in case_fields),
                *(f"{case}.{stage}.{field}" for case in cases for stage in stages for field in stage_fields)}
    if set(trace) != expected or any(trace[key] != value for key, value in geometry.items()):
        raise harness.HarnessError(f"{description} lacks the complete normal-bin allocation image")
    for case, request in cases.items():
        words = (request + 7) // 8
        selected_size = (8 if words <= 1 else ((words + 1) & ~1) * 8) if request <= 64 else request
        bin_index = next(index for index, size in enumerate(sizes, 1) if size >= selected_size)
        usable = sizes[bin_index - 1]
        if any(trace[f"{case}.{field}"] != str(value) for field, value in (
            ("request", request), ("usable", usable), ("bin_index", bin_index),
            ("zero_all", 1), ("distinct", 1),
        )):
            raise harness.HarnessError(f"{description} lost {case} page geometry or calloc zeroing")
        for stage in stages:
            if stage == "prepared":
                for field, total, current in (
                    ("normal", 2 * usable if level else 0, usable if level else 0),
                    ("requested", 2 * request if level == 2 else 0, 2 * request if level == 2 else 0),
                    ("bin", 2 if level == 2 else 0, 1 if level == 2 else 0),
                    ("huge", 0, 0),
                ):
                    try:
                        observed_total, observed_peak, observed_current = map(
                            int, trace[f"{case}.{stage}.{field}"].split(","))
                    except ValueError as error:
                        raise harness.HarnessError(f"{description} malformed {case} prepared {field}") from error
                    if ((observed_total, observed_current) != (total, current)
                            or not 0 <= observed_peak <= total):
                        raise harness.HarnessError(f"{description} lost {case} initial {field} allocation")
                if trace[f"{case}.prepared.normal_count"] != ("2" if level == 2 else "0"):
                    raise harness.HarnessError(f"{description} lost {case} initial allocation count")
                continue
            current = 1 if stage in ("allocated", "merged", "reset") else -1 if stage == "terminal" else 0
            expected_stage = {
                "normal": f"{usable},0,{current * usable}" if level else "0,0,0",
                "huge": "0,0,0",
                "requested": f"{request},{request},{request}" if level == 2 else "0,0,0",
                "bin": f"1,0,{current}" if level == 2 else "0,0,0",
                "normal_count": "1" if level == 2 else "0",
                "page_bin_current": "0", "searches": "0", "extensions": "0",
            }
            for field, value in expected_stage.items():
                if trace[f"{case}.{stage}.{field}"] != value:
                    raise harness.HarnessError(
                        f"{description} lost {case} {stage} {field}: "
                        f"{trace[f'{case}.{stage}.{field}']} != {value}")


def require_statistics_requested_production(trace: Mapping[str, str], description: str) -> None:
    """Require the owner merges and two distinct allocation-bin lifetimes."""

    stages = ("ordinary", "ordinary_merged", "aligned", "aligned_merged",
              "ordinary_freed", "aligned_freed", "final_merged")
    fields = ("requested", "ordinary_bin", "aligned_bin", "normal_count", "huge_count")
    expected = {"profile.level", "ordinary.request", "ordinary.usable", "ordinary.bin",
                "aligned.request", "aligned.usable", "aligned.bin", "aligned.pointer",
                *(f"{stage}.{field}" for stage in stages for field in fields)}
    if set(trace) != expected or trace["profile.level"] != "2":
        raise harness.HarnessError(f"{description} lacks the requested-size production image: {trace}")
    try:
        ordinary_request = int(trace["ordinary.request"])
        aligned_request = int(trace["aligned.request"])
        ordinary_usable = int(trace["ordinary.usable"])
        aligned_usable = int(trace["aligned.usable"])
        ordinary_bin = int(trace["ordinary.bin"])
        aligned_bin = int(trace["aligned.bin"])
        counts = {stage: {field: tuple(int(part) for part in trace[f"{stage}.{field}"].split(","))
                          if field in ("requested", "ordinary_bin", "aligned_bin")
                          else int(trace[f"{stage}.{field}"])
                          for field in fields} for stage in stages}
    except ValueError as error:
        raise harness.HarnessError(f"{description} has a nonnumeric production field: {trace}") from error
    if (ordinary_request != 63 or ordinary_usable != 64 or aligned_request != 100
            or aligned_usable <= aligned_request or trace["aligned.pointer"] != "1"
            or ordinary_bin == aligned_bin or ordinary_bin <= 0 or aligned_bin <= 0
            or any(len(counts[stage][field]) != 3 for stage in stages for field in fields[:3])):
        raise harness.HarnessError(f"{description} did not select two physical bins: {trace}")
    internal_aligned_request = counts["aligned"]["requested"][0] - ordinary_request
    expected_by_stage = {
        "ordinary": ((ordinary_request,) * 3, (1, 1, 1), (0, 0, 0), 1, 0),
        "ordinary_merged": ((ordinary_request,) * 3, (1, 1, 1), (0, 0, 0), 1, 0),
        "aligned": ((ordinary_request + internal_aligned_request,) * 3, (1, 1, 1), (1, 1, 1), 2, 1),
        "aligned_merged": ((ordinary_request + internal_aligned_request,) * 3, (1, 1, 1), (1, 1, 1), 2, 1),
        "ordinary_freed": ((ordinary_request + internal_aligned_request,) * 3, (1, 1, 0), (1, 1, 1), 2, 1),
        "aligned_freed": ((ordinary_request + internal_aligned_request,) * 3, (1, 1, 0), (1, 1, 0), 2, 1),
        "final_merged": ((ordinary_request + internal_aligned_request,) * 3, (1, 1, 0), (1, 1, 0), 2, 1),
    }
    if internal_aligned_request != 1025 or any(
        tuple(counts[stage][field] for field in fields) != expected_by_stage[stage]
        for stage in stages
    ):
        raise harness.HarnessError(f"{description} lost a source requested/bin/count transition: {trace}")


def require_statistics_level_one(trace: Mapping[str, str], description: str) -> None:
    """Require a live binned count that survives reset and drops on free."""

    try:
        usable = int(trace["allocation.usable"])
        allocated = tuple(int(part) for part in trace["allocated.normal"].split(","))
        merged = tuple(int(part) for part in trace["merged.normal"].split(","))
        freed = tuple(int(part) for part in trace["freed.normal"].split(","))
    except (KeyError, ValueError) as error:
        raise harness.HarnessError(f"{description} lacks a numeric level-one count: {trace}") from error
    if (set(trace) != {"profile.level", "allocation.usable", "allocated.normal", "merged.normal",
                       "freed.normal", "print.live_binned", "print.live_total",
                       "print.freed_binned", "print.freed_total"}
            or trace["profile.level"] != "1"
            or any(trace[key] != "1" for key in ("print.live_binned", "print.live_total",
                                                   "print.freed_binned", "print.freed_total"))
            or usable < 64 or len(allocated) != 3 or len(merged) != 3 or len(freed) != 3
            or allocated[0] != usable or allocated[2] != usable
            or merged != allocated or freed != (allocated[0], allocated[1], 0)):
        raise harness.HarnessError(f"{description} violates the binned merge/reset/free path: {trace}")


def require_statistics_level_one_output_merge(trace: Mapping[str, str], description: str) -> None:
    """Require separate source merges and every malloc presentation state."""

    scenarios = ("empty", "normal", "huge", "mixed", "freed")
    rows = ("binned", "huge", "total")
    counts = ("normal.source_reset", "normal.process", "huge.source_reset", "huge.process",
              "mixed.source_normal_reset", "mixed.source_huge_reset", "mixed.process_normal",
              "mixed.process_huge", "freed.source_normal_reset", "freed.source_huge_reset",
              "freed.process_normal", "freed.process_huge")
    expected = {"profile.level", *(f"{scenario}.{row}" for scenario in scenarios for row in rows), *counts}
    if set(trace) != expected or trace["profile.level"] != "1":
        raise harness.HarnessError(f"{description} lacks the selected level-one merge/output fields: {trace}")
    try:
        values = {key: tuple(int(part) for part in trace[key].split(",")) for key in counts}
    except ValueError as error:
        raise harness.HarnessError(f"{description} has a nonnumeric merge field: {trace}") from error
    if (any(len(value) != 3 for value in values.values())
            or any(values[key] != (0, 0, 0) for key in counts if key.endswith("reset"))
            or values["normal.process"][2] <= 0 or values["huge.process"][2] <= 0
            or values["mixed.process_normal"][0] <= values["normal.process"][0]
            or values["mixed.process_huge"][0] != values["huge.process"][0]
            or values["freed.process_normal"][2] != 0 or values["freed.process_huge"][2] != 0):
        raise harness.HarnessError(f"{description} lost a source merge/reset transition: {trace}")
    if (any(trace[f"empty.{row}"] != "absent" for row in rows)
            or any(trace[f"{scenario}.{row}"] == "absent"
                   for scenario in scenarios[1:] for row in rows)
            or "not all freed" not in trace["normal.binned"]
            or "not all freed" not in trace["mixed.huge"]
            or any(not trace[f"freed.{row}"].endswith("  ok") for row in rows)):
        raise harness.HarnessError(f"{description} lost an empty, live, or freed malloc row: {trace}")


def require_statistics_level_two_requested(trace: Mapping[str, str], description: str) -> None:
    """Require the level-two requested row across empty, live, and freed merges."""

    scenarios = ("empty", "normal", "live", "freed")
    rows = ("blocks", "binned", "huge", "total", "malloc_req")
    counts = ("normal.source_requested_reset", "normal.process_requested", "normal.process_count",
              "live.source_requested_reset", "live.process_requested", "live.process_count",
              "freed.source_requested_reset", "freed.process_requested")
    expected = {"profile.level", *(f"{scenario}.{row}" for scenario in scenarios for row in rows), *counts}
    if set(trace) != expected or trace["profile.level"] != "2":
        raise harness.HarnessError(f"{description} lacks the selected level-two requested fields: {trace}")
    try:
        normal = tuple(int(part) for part in trace["normal.process_requested"].split(","))
        live = tuple(int(part) for part in trace["live.process_requested"].split(","))
        freed = tuple(int(part) for part in trace["freed.process_requested"].split(","))
    except ValueError as error:
        raise harness.HarnessError(f"{description} has a nonnumeric requested count: {trace}") from error
    if (len(normal) != 3 or len(live) != 3 or len(freed) != 3
            or any(trace[key] != "0,0,0" for key in counts if key.endswith("reset"))
            or normal[1] <= 0 or live[1] <= normal[1] or live[2] <= normal[2]
            or freed != (live[0], live[1], 0)
            or trace["normal.process_count"] != "2" or trace["live.process_count"] != "2,1"
            or trace["empty.blocks"] != "0" or any(trace[f"{scenario}.blocks"] != "1" for scenario in scenarios[1:])
            or any(trace[f"empty.{row}"] != "absent" for row in rows[1:])
            or any(trace[f"{scenario}.{row}"] == "absent" for scenario in scenarios[1:] for row in rows[1:])
            or trace["live.malloc_req"] != trace["freed.malloc_req"]):
        raise harness.HarnessError(f"{description} lost a requested merge or display state: {trace}")


def require_statistics_level_two_bins(trace: Mapping[str, str], description: str) -> None:
    """Require two ordered, merged bin rows and suppress an empty middle bin."""

    scenarios = ("empty", "first", "merged", "freed")
    row_keys = ("order", "bin8", "bin9", "bin40")
    counts = ("first.source_bin8_reset", "first.process_bin8", "merged.source_bin8_reset",
              "merged.source_bin40_reset", "merged.process_bin8", "merged.process_bin40",
              "freed.source_bin8_reset", "freed.source_bin40_reset", "freed.process_bin8",
              "freed.process_bin40")
    expected = {"profile.level", *(f"{scenario}.{key}" for scenario in scenarios for key in row_keys), *counts}
    if set(trace) != expected or trace["profile.level"] != "2":
        raise harness.HarnessError(f"{description} lacks the level-two bin trace fields: {trace}")
    if (any(trace[key] != "0,0,0" for key in counts if key.endswith("reset"))
            or trace["first.process_bin8"] != "2,3,1"
            or trace["merged.process_bin8"] != "5,8,3"
            or trace["merged.process_bin40"] != "2,3,1"
            or trace["freed.process_bin8"] != "5,8,0"
            or trace["freed.process_bin40"] != "2,3,0"
            or [trace[f"{scenario}.order"] for scenario in scenarios] != ["none", "8", "8,40", "8,40"]
            or any(trace[f"{scenario}.bin9"] != "absent" for scenario in scenarios)
            or trace["empty.bin8"] != "absent" or trace["empty.bin40"] != "absent"
            or trace["first.bin8"] == "absent" or trace["first.bin40"] != "absent"
            or any(trace[f"{scenario}.bin8"] == "absent" or trace[f"{scenario}.bin40"] == "absent"
                   for scenario in ("merged", "freed"))
            or "not all freed" not in trace["merged.bin8"]
            or not trace["freed.bin8"].endswith("  ok")
            or not trace["freed.bin40"].endswith("  ok")):
        raise harness.HarnessError(f"{description} lost the source bin merge or final row behavior: {trace}")


def require_statistics_level_two_page_huge(trace: Mapping[str, str], description: str) -> None:
    """Require separate section guards, owner resets, and live/freed rows."""

    scenarios = ("empty", "huge", "live", "freed")
    rows = ("order", "huge", "touched", "pages", "abandoned")
    counts = ("huge.source_reset", "huge.process", "live.source_huge_reset",
              "live.source_pages_reset", "live.process_huge", "live.process_pages",
              "live.process_touched", "live.process_abandoned", "freed.source_huge_reset",
              "freed.source_pages_reset", "freed.process_huge", "freed.process_pages",
              "freed.process_touched", "freed.process_abandoned")
    expected = {"profile.level", *(f"{scenario}.{row}" for scenario in scenarios for row in rows), *counts}
    if set(trace) != expected or trace["profile.level"] != "2":
        raise harness.HarnessError(f"{description} lacks the level-two huge/page trace fields: {trace}")
    values = {
        "huge.process": "4096,8192,4096", "live.process_huge": "10240,20480,6144",
        "live.process_pages": "4,6,3", "live.process_touched": "16384,24576,12288",
        "live.process_abandoned": "2,3,1", "freed.process_huge": "10240,20480,0",
        "freed.process_pages": "4,6,0", "freed.process_touched": "16384,24576,0",
        "freed.process_abandoned": "2,3,0",
    }
    if (any(trace[key] != "0,0,0" for key in counts if key.endswith("reset"))
            or any(trace[key] != value for key, value in values.items())
            or [trace[f"{scenario}.order"] for scenario in scenarios]
            != ["none", "blocks", "blocks,pages", "blocks,pages"]
            or any(trace[f"empty.{row}"] != "absent" for row in rows[1:])
            or any(trace[f"huge.{row}"] != "absent" for row in ("touched", "pages", "abandoned"))
            or "not all freed" not in trace["live.huge"]
            or "not all freed" in trace["live.touched"]
            or any("not all freed" in trace[f"live.{row}"] or trace[f"live.{row}"].endswith("ok")
                   for row in ("pages", "abandoned"))
            or any(not trace[f"freed.{row}"].endswith("  ok") for row in ("huge", "touched"))
            or any("ok" in trace[f"freed.{row}"] for row in ("pages", "abandoned"))):
        raise harness.HarnessError(f"{description} lost a huge/page merge or display state: {trace}")


def require_statistics_json(trace: Mapping[str, str], level: int, description: str) -> None:
    """Require caller-buffer boundaries and source image values in every profile."""

    expected = {
        "profile.level", "json.grown", "json.version", "json.mimalloc_version",
        "json.process", "json.chunk_bins", "json.hash", "json.pages",
        "json.malloc_normal", "json.malloc_huge", "json.malloc_requested",
        "json.malloc_bins.bin8", "json.page_bins.bin8",
        *(f"fixed.{name}.{field}" for name in ("one", "two", "three", "sixtyfour")
          for field in ("result", "prefix", "guard")),
        "fixed.sufficient.result", "fixed.sufficient.complete", "fixed.sufficient.guard",
        "zero_size.grown",
        "zero_size.caller_intact", "null_buffer.grown", "invalid.version",
        "invalid.caller_intact", "invalid.null_image", "get.grown", "get.version",
        "get.short", "get.short.prefix", "get.short.guard",
    }
    if set(trace) != expected or trace["profile.level"] != str(level):
        raise harness.HarnessError(f"{description} lacks the JSON caller trace fields: {trace}")
    required = {
        "json.grown": "1", "json.version": "1", "json.mimalloc_version": "1",
        "json.process": "1", "json.chunk_bins": "1", "json.pages": "6,4,3",
        "json.malloc_normal": "320,160,96", "json.malloc_huge": "8192,4096,2048",
        "json.malloc_requested": "280,140,70",
        "fixed.one.result": "0", "fixed.one.prefix": "00", "fixed.one.guard": "1",
        "fixed.two.result": "0", "fixed.two.prefix": "7b00", "fixed.two.guard": "1",
        "fixed.three.result": "0", "fixed.three.prefix": "7b0a00", "fixed.three.guard": "1",
        "fixed.sixtyfour.result": "0", "fixed.sixtyfour.guard": "1",
        "fixed.sufficient.result": "1", "fixed.sufficient.complete": "1",
        "fixed.sufficient.guard": "1",
        "zero_size.grown": "1", "zero_size.caller_intact": "1",
        "null_buffer.grown": "1", "invalid.version": "1",
        "invalid.caller_intact": "1", "invalid.null_image": "1",
        "get.grown": "1", "get.version": "1", "get.short": "0",
        "get.short.prefix": "7b0a00", "get.short.guard": "1",
    }
    if (any(trace[key] != value for key, value in required.items())
            or not re.fullmatch(r"[0-9a-f]{16}", trace["json.hash"])
            or not re.fullmatch(r"[0-9a-f]{16}", trace["fixed.sixtyfour.prefix"])
            or not trace["json.malloc_bins.bin8"].startswith("5,4,2,")
            or not trace["json.page_bins.bin8"].startswith("3,2,1,")):
        raise harness.HarnessError(f"{description} lost JSON serialization or caller-buffer behavior: {trace}")


def require_statistics_page_extend(
    trace: Mapping[str, str], description: str, *, repeated: bool = False,
    faulted: bool = False,
) -> None:
    """Require source page-extension counts, commit outcomes, and page lifetime."""

    if repeated and faulted:
        raise harness.HarnessError("page extension profiles are mutually exclusive")
    if faulted:
        expected = {
            "profile.level": "2", "profile.on_demand": "1",
            "profile.eager_arena": "0", "profile.show_errors": "1",
            "failed_allocation.same_page": "0", "failed_allocation.nonnull": "1",
            "retry.same_page": "1", "retry.nonnull": "1",
        }
        for stage, extension_count, page_bytes, pages, requested, normal, bin_count, page_bin, commit_calls, warnings in (
            ("filled", 1, 8192, "1,1,1", 8192, "8192,8192,8192", "128,128,128", "1,1", 3, 0),
            ("failed_allocation", 3, 16384, "2,2,2", 8256, "8256,8256,8256", "129,129,129", "2,2", 5, 1),
            ("retry", 4, 24576, "2,2,1", 8320, "8320,8256,8256", "130,129,129", "2,1", 6, 1),
            ("freed", 4, 24576, "2,2,1", 8320, "8320,8256,0", "130,129,0", "2,1", 6, 1),
        ):
            expected[f"{stage}.pages_extended"] = str(extension_count)
            expected[f"{stage}.page_committed"] = f"{page_bytes},{page_bytes},{page_bytes}"
            expected[f"{stage}.pages"] = pages
            expected[f"{stage}.requested"] = f"{requested},{requested},{requested}"
            expected[f"{stage}.normal"] = normal
            expected[f"{stage}.bin"] = f"8:{bin_count}"
            expected[f"{stage}.page_bin"] = f"8:{page_bin}"
            expected[f"{stage}.commit_calls"] = str(commit_calls)
            expected[f"{stage}.warnings"] = str(warnings)
            expected[f"{stage}.failures"] = "0" if stage == "filled" else "1"
    elif repeated:
        expected = {"profile.level": "1", "page.same_slice": "1"}
        for stage, extension_count, committed in (
            ("one", 1, 8192), ("one_twenty_eight", 1, 8192),
            ("one_twenty_nine", 2, 16384), ("two_sixty", 3, 24576),
            ("freed", 3, 24576),
        ):
            expected[f"{stage}.pages_extended"] = str(extension_count)
            expected[f"{stage}.page_committed"] = f"{committed},{committed},{committed}"
            expected[f"{stage}.pages"] = "1,1,1"
    else:
        expected = {
            "profile.level": "1", "allocation.usable": "64",
            "allocated.pages_extended": "1", "allocated.page_committed": "8192,8192,8192",
            "allocated.pages": "1,1,1", "freed.pages_extended": "1",
            "freed.page_committed": "8192,8192,8192",
        }
    if dict(trace) != expected:
        raise harness.HarnessError(f"{description} lost the source page-extension producer: {trace}")


def require_statistics_huge(trace: Mapping[str, str], description: str) -> None:
    """Require the physical huge-page count before and after nonlocal free."""

    expected = {
        "profile.level": "1", "allocation.usable": "589824",
        "allocated.huge": "589824,589824,589824", "allocated.huge_count": "1",
        "allocated.normal": "0", "freed.huge": "589824,589824,0",
        "freed.huge_count": "1",
    }
    if dict(trace) != expected:
        raise harness.HarnessError(f"{description} lost the source huge-page producer: {trace}")


def require_statistics_remote_normal(trace: Mapping[str, str], description: str) -> None:
    """Require a negative freeing-Theap current before its process merge."""

    expected = {
        "profile.level": "1", "warm.usable": "8", "target.usable": "64",
        "worker.fresh": "0",
        "allocated.normal": "64,64,64", "freed.normal": "72,72,0",
        "worker.binned.hex": trace.get("worker.binned.hex"),
    }
    if dict(trace) != expected:
        raise harness.HarnessError(f"{description} lost the remote normal-byte producer: {trace}")
    try:
        worker_row = bytes.fromhex(trace["worker.binned.hex"]).decode("ascii")
    except (ValueError, UnicodeDecodeError) as error:
        raise harness.HarnessError(f"{description} has invalid worker statistics text") from error
    if worker_row.split() != ["binned", ":", "8", "8", "-64", "not", "all", "freed"]:
        raise harness.HarnessError(f"{description} lost the freeing-Theap peak/current: {worker_row}")


def require_statistics_remote_normal_fresh(
    trace: Mapping[str, str], description: str, *, checked_free: bool = False,
    queried_usable: bool = False,
) -> None:
    """Require an uninitialized freeing worker's metadata-Theap accounting."""

    allocated = {
        "bin": "1,1,1", "normal": "32768,32768,32768",
        "normal_count": "1", "page_bin": "1,1,1",
        "pages": "1,1,1", "requested": "32768,32768,32768",
    }
    expected = {
        "profile.level": "2", "worker.fresh": "1", "warm.usable": "0",
        "target.request": "32768", "target.usable": "32768",
        "worker.free_usable": "0" if checked_free else "32768",
        "worker.cfree_owned": "1" if checked_free else "0",
        "worker.binned.hex": "",
    }
    if queried_usable:
        expected["worker.query_usable"] = "32768"
    for stage in ("allocated", "freed"):
        expected.update({f"{stage}.{field}": value for field, value in allocated.items()})
    if dict(trace) != expected:
        raise harness.HarnessError(f"{description} lost the fresh-worker medium free statistics: {trace}")


def require_statistics_aligned_huge(trace: Mapping[str, str], description: str) -> None:
    """Require the aligned page's physical bytes and byte-unit print before merge."""

    expected = {
        "profile.level": "1", "allocation.aligned": "1", "allocation.usable": "589824",
        "allocated.huge": "589824,589824,589824", "allocated.huge_count": "1",
        "merged.huge": "589824,589824,589824", "merged.huge_count": "1",
        "freed.huge": "589824,589824,0", "freed.huge_count": "1",
        "thread.live_huge": "1", "thread.live_huge.hex": trace.get("thread.live_huge.hex"),
        "warning.count": "0",
    }
    if dict(trace) != expected:
        raise harness.HarnessError(f"{description} lost aligned huge accounting or warning behavior: {trace}")
    try:
        row = bytes.fromhex(trace["thread.live_huge.hex"]).decode("ascii")
    except (ValueError, UnicodeDecodeError) as error:
        raise harness.HarnessError(f"{description} has invalid huge statistics text") from error
    if row.split() != ["huge", ":", "578.2", "KiB", "578.2", "KiB", "578.2", "KiB",
                       "not", "all", "freed"]:
        raise harness.HarnessError(f"{description} lost the pre-merge physical-byte row: {row}")


def run_statistics_level_one_differential(offline: bool) -> dict[str, Any]:
    """Build the same public statistics driver with pinned C level one and Rust."""

    import x86_64_m4_gate as m4

    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory("crabc-mimalloc-x86_64-m7-statistics-level-one-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "statistics-level-one-c"
        configuration = ["-DMI_STAT=1" if flag == "-DMI_STAT=0" else flag
                         for flag in harness.CONFIGURATION_PROFILES["release"]]
        c_build = harness.command_record([
            compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
            *configuration, "-I", str(source / "include"), str(STATISTICS_LEVEL_ONE_DRIVER),
            str(source / "src/static.c"), "-pthread", "-o", str(c_driver),
        ], cwd=source, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
        harness.require_success(c_build, "pinned C level-one statistics driver build")
        target_dir = temporary / "cargo-target"
        adapter_build = harness.command_record([
            harness.require_tool("cargo"), "build", "--locked", "--release", "--target", m4.RUST_TARGET,
            "-p", m4.ADAPTER_PACKAGE, "--features", "crabc-mimalloc/mi-stat-1",
            "--target-dir", str(target_dir),
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
        harness.require_success(adapter_build, "Rust level-one statistics adapter build")
        library = target_dir / m4.RUST_TARGET / "release" / m4.ADAPTER_STATICLIB
        rust_driver = temporary / "statistics-level-one-rust"
        rust_build = harness.command_record([
            compiler, "-std=c11", "-O2", "-I", str(source / "include"),
            str(STATISTICS_LEVEL_ONE_DRIVER), str(library), "-pthread", "-o", str(rust_driver),
        ], cwd=source, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
        harness.require_success(rust_build, "Rust level-one statistics driver link")
        executions = {
            side: harness.command_record([str(driver)], cwd=temporary, env={}, timeout_seconds=60)
            for side, driver in (("c", c_driver), ("rust", rust_driver))
        }
        for side, execution in executions.items():
            harness.require_success(execution, f"{side} level-one statistics driver")
        traces = {
            side: parse_options_trace(str(execution["stdout"]), f"{side} level-one statistics",
                                      STATISTICS_LEVEL_ONE_TRACE_BEGIN, STATISTICS_LEVEL_ONE_TRACE_END)
            for side, execution in executions.items()
        }
        for side, trace in traces.items():
            require_statistics_level_one(trace, side)
        compare_options_traces(traces["c"], traces["rust"])
        report = {"c_build_command": c_build["command"], "adapter_build_command": adapter_build["command"],
                  "rust_build_command": rust_build["command"],
                  "trace": traces["c"], "c_trace": traces["c"], "rust_trace": traces["rust"],
                  "status": "passed"}
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    harness.write_json(ARTIFACTS / "statistics-level-one.json", report)
    return report


def run_statistics_level_one_output_merge_differential(offline: bool) -> dict[str, Any]:
    return run_trace_differential(
        offline, subject="statistics-level-one-output-merge", oracle=STATISTICS_LEVEL_ONE_OUTPUT_MERGE_ORACLE,
        test=STATISTICS_LEVEL_ONE_OUTPUT_MERGE_TEST, begin=STATISTICS_LEVEL_ONE_OUTPUT_MERGE_TRACE_BEGIN,
        end=STATISTICS_LEVEL_ONE_OUTPUT_MERGE_TRACE_END,
        require_complete=require_statistics_level_one_output_merge,
        report_name="statistics-level-one-output-merge.json", compile_defines=("-DMI_STAT=1",),
        rust_features=("mi-stat-1",),
    )


def run_statistics_level_two_requested_differential(offline: bool) -> dict[str, Any]:
    return run_trace_differential(
        offline, subject="statistics-level-two-requested", oracle=STATISTICS_LEVEL_TWO_REQUESTED_ORACLE,
        test=STATISTICS_LEVEL_TWO_REQUESTED_TEST, begin=STATISTICS_LEVEL_TWO_REQUESTED_TRACE_BEGIN,
        end=STATISTICS_LEVEL_TWO_REQUESTED_TRACE_END,
        require_complete=require_statistics_level_two_requested,
        report_name="statistics-level-two-requested.json", compile_defines=("-DMI_STAT=2",),
        rust_features=("mi-stat-2",),
    )


def run_statistics_level_two_bins_differential(offline: bool) -> dict[str, Any]:
    return run_trace_differential(
        offline, subject="statistics-level-two-bins", oracle=STATISTICS_LEVEL_TWO_BINS_ORACLE,
        test=STATISTICS_LEVEL_TWO_BINS_TEST, begin=STATISTICS_LEVEL_TWO_BINS_TRACE_BEGIN,
        end=STATISTICS_LEVEL_TWO_BINS_TRACE_END, require_complete=require_statistics_level_two_bins,
        report_name="statistics-level-two-bins.json", compile_defines=("-DMI_STAT=2",),
        rust_features=("mi-stat-2",),
    )


def run_statistics_level_two_page_huge_differential(offline: bool) -> dict[str, Any]:
    return run_trace_differential(
        offline, subject="statistics-level-two-page-huge", oracle=STATISTICS_LEVEL_TWO_PAGE_HUGE_ORACLE,
        test=STATISTICS_LEVEL_TWO_PAGE_HUGE_TEST, begin=STATISTICS_LEVEL_TWO_PAGE_HUGE_TRACE_BEGIN,
        end=STATISTICS_LEVEL_TWO_PAGE_HUGE_TRACE_END,
        require_complete=require_statistics_level_two_page_huge,
        report_name="statistics-level-two-page-huge.json", compile_defines=("-DMI_STAT=2",),
        rust_features=("mi-stat-2",),
    )


def run_statistics_json_differential(offline: bool) -> dict[str, Any]:
    """Compare the public JSON buffer contract under each selected stats level."""

    import x86_64_m4_gate as m4

    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    profiles: dict[str, Any] = {}
    with harness.temporary_directory("crabc-mimalloc-x86_64-m7-statistics-json-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        for level in (0, 1, 2):
            profile = temporary / f"stat-{level}"
            profile.mkdir()
            c_binary = profile / "json-c"
            c_build = harness.command_record(
                [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                 *harness.CONFIGURATION_PROFILES["release"], f"-DMI_STAT={level}",
                 "-I", str(source / "include"), str(STATISTICS_JSON_ORACLE),
                 str(source / "src/static.c"), "-pthread", "-o", str(c_binary)], cwd=source,
            )
            harness.require_success(c_build, f"M7 MI_STAT={level} JSON C build")
            feature = () if level == 0 else ("--features", f"crabc-mimalloc/mi-stat-{level}")
            target = profile / "cargo-target"
            rust_build = harness.command_record(
                [harness.require_tool("cargo"), "build", "--locked", "--release", "--target",
                 RUST_TARGET, "-p", m4.ADAPTER_PACKAGE, "--no-default-features", *feature,
                 "--target-dir", str(target)], cwd=harness.ROOT, env=dict(os.environ),
                timeout_seconds=EVIDENCE_TIMEOUT_SECONDS,
            )
            harness.require_success(rust_build, f"M7 MI_STAT={level} JSON Rust adapter build")
            rust_binary = profile / "json-rust"
            rust_link = harness.command_record(
                [compiler, "-std=c11", "-O2", f"-DMI_STAT={level}",
                 "-I", str(source / "include"), str(STATISTICS_JSON_ORACLE),
                 str(target / RUST_TARGET / "release" / m4.ADAPTER_STATICLIB),
                 "-pthread", "-o", str(rust_binary)], cwd=source,
            )
            harness.require_success(rust_link, f"M7 MI_STAT={level} JSON Rust driver link")
            traces = {}
            for side, binary in (("c", c_binary), ("rust", rust_binary)):
                execution = harness.command_record((str(binary),), cwd=profile, env={}, timeout_seconds=600)
                harness.require_success(execution, f"M7 MI_STAT={level} JSON {side} execution")
                trace = parse_options_trace(str(execution["stdout"]),
                    f"M7 MI_STAT={level} JSON {side}", STATISTICS_JSON_TRACE_BEGIN, STATISTICS_JSON_TRACE_END)
                require_statistics_json(trace, level, f"M7 MI_STAT={level} JSON {side}")
                traces[side] = trace
            compare_options_traces(traces["c"], traces["rust"])
            profiles[str(level)] = {"status": "passed", "compared_key_count": len(traces["c"]),
                                    "trace": traces["c"], "c_build": c_build["command"],
                                    "rust_build": rust_build["command"]}
    report = {"status": "passed", "profiles": profiles,
              "compared_key_count": sum(value["compared_key_count"] for value in profiles.values())}
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    harness.write_json(ARTIFACTS / "statistics-json.json", report)
    return report


def run_public_statistics_differential(
    offline: bool, *, subject: str, driver: Path, begin: str, end: str,
    report_name: str, require_complete: Any | None = None, stat_level: int = 1,
    comparison_excluded_keys: frozenset[str] = frozenset(),
    driver_defines: tuple[str, ...] = (),
    retain_artifacts: bool = False,
) -> dict[str, Any]:
    """Run one public statistics driver with pinned C and the selected adapter profile."""

    import x86_64_m4_gate as m4

    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory(f"crabc-mimalloc-x86_64-m7-statistics-{subject}-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_binary = temporary / f"{subject}-c"
        c_build = harness.command_record(
            [compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
             *harness.CONFIGURATION_PROFILES["release"], f"-DMI_STAT={stat_level}",
             *driver_defines,
             "-I", str(source / "include"), str(driver),
             str(source / "src/static.c"), "-pthread", "-o", str(c_binary)], cwd=source,
        )
        harness.require_success(c_build, f"M7 {subject} C build")
        target = temporary / "cargo-target"
        rust_build = harness.command_record(
            [harness.require_tool("cargo"), "build", "--locked", "--release", "--target",
             RUST_TARGET, "-p", m4.ADAPTER_PACKAGE,
             *(("--features", f"crabc-mimalloc/mi-stat-{stat_level}") if stat_level else ()),
             "--target-dir", str(target)], cwd=harness.ROOT, env=dict(os.environ),
             timeout_seconds=EVIDENCE_TIMEOUT_SECONDS,
        )
        harness.require_success(rust_build, f"M7 {subject} Rust adapter build")
        rust_binary = temporary / f"{subject}-rust"
        rust_link = harness.command_record(
            [compiler, "-std=c11", "-O2", *driver_defines, "-I", str(source / "include"),
             str(driver),
             str(target / RUST_TARGET / "release" / m4.ADAPTER_STATICLIB),
             "-pthread", "-o", str(rust_binary)], cwd=source,
        )
        harness.require_success(rust_link, f"M7 {subject} Rust driver link")
        traces = {}
        executions = {}
        artifacts = {}
        for side, binary in (("c", c_binary), ("rust", rust_binary)):
            execution = harness.command_record((str(binary),), cwd=temporary, env={}, timeout_seconds=60)
            harness.require_success(execution, f"M7 {subject} {side} execution")
            traces[side] = parse_options_trace(str(execution["stdout"]),
                f"M7 {subject} {side}", begin, end)
            if retain_artifacts:
                retained = ARTIFACTS / subject
                retained.mkdir(parents=True, exist_ok=True)
                product = retained / binary.name
                shutil.copy2(binary, product)
                for stream in ("stdout", "stderr"):
                    (retained / f"{side}.{stream}").write_text(execution[stream], encoding="utf-8")
                artifacts[side] = engine.file_record(product)
                executions[side] = execution
        if retain_artifacts:
            shutil.copy2(driver, retained / driver.name)
            artifacts["driver"] = engine.file_record(retained / driver.name)
            archive_product = retained / m4.ADAPTER_STATICLIB
            shutil.copy2(target / RUST_TARGET / "release" / m4.ADAPTER_STATICLIB, archive_product)
            artifacts["rust_archive"] = engine.file_record(archive_product)
    report = {"status": "failed", "c_trace": traces["c"], "rust_trace": traces["rust"],
              "c_build": c_build["command"], "rust_build": rust_build["command"],
              "comparison_excluded_keys": sorted(comparison_excluded_keys)}
    if retain_artifacts:
        report.update({"artifacts": artifacts, "executions": executions, "stat_level": stat_level,
                       "pin": pin, "rust_link": rust_link["command"],
                       "builds": {"c": c_build, "rust": rust_build, "rust_link": rust_link}})
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    harness.write_json(ARTIFACTS / report_name, report)
    if require_complete is not None:
        require_complete(traces["c"], f"pinned C {subject}")
        require_complete(traces["rust"], f"Rust {subject}")
    if any(not comparison_excluded_keys <= set(trace) for trace in traces.values()):
        raise harness.HarnessError(f"M7 {subject} omitted a raw comparison baseline")
    compared = {side: {key: value for key, value in trace.items()
                       if key not in comparison_excluded_keys}
                for side, trace in traces.items()}
    compare_options_traces(compared["c"], compared["rust"])
    report["compared_key_count"] = len(compared["c"])
    report["status"] = "passed"
    harness.write_json(ARTIFACTS / report_name, report)
    return report


def run_statistics_page_extend_differential(offline: bool) -> dict[str, Any]:
    return run_public_statistics_differential(
        offline, subject="page-extend", driver=STATISTICS_PAGE_EXTEND_DRIVER,
        begin=STATISTICS_PAGE_EXTEND_TRACE_BEGIN, end=STATISTICS_PAGE_EXTEND_TRACE_END,
        report_name="statistics-page-extend.json", require_complete=require_statistics_page_extend,
    )


def run_statistics_page_second_extension_differential(offline: bool) -> dict[str, Any]:
    return run_public_statistics_differential(
        offline, subject="page-second-extension", driver=STATISTICS_PAGE_SECOND_EXTENSION_DRIVER,
        begin=STATISTICS_PAGE_SECOND_EXTENSION_TRACE_BEGIN,
        end=STATISTICS_PAGE_SECOND_EXTENSION_TRACE_END,
        report_name="statistics-page-second-extension.json", stat_level=1,
        require_complete=lambda trace, description: require_statistics_page_extend(
            trace, description, repeated=True,
        ),
    )


def run_statistics_huge_differential(offline: bool) -> dict[str, Any]:
    return run_public_statistics_differential(
        offline, subject="huge", driver=STATISTICS_HUGE_DRIVER,
        begin=STATISTICS_HUGE_TRACE_BEGIN, end=STATISTICS_HUGE_TRACE_END,
        report_name="statistics-huge.json", require_complete=require_statistics_huge,
    )


def run_statistics_huge_page_bin_differential(offline: bool) -> dict[str, Any]:
    # Worker setup may change prior mmap history; preserve the raw arena
    # snapshots while requiring no growth through this selected singleton.
    return run_public_statistics_differential(
        offline, subject="huge-page-bin", driver=STATISTICS_HUGE_PAGE_BIN_DRIVER,
        begin=STATISTICS_HUGE_PAGE_BIN_TRACE_BEGIN, end=STATISTICS_HUGE_PAGE_BIN_TRACE_END,
        report_name="statistics-huge-page-bin.json", stat_level=2,
        require_complete=require_statistics_huge_page_bin,
        comparison_excluded_keys=frozenset({"before.arena", "allocated.arena", "terminal.arena"}),
    )


def run_statistics_huge_page_bin_fresh_differential(offline: bool) -> dict[str, Any]:
    return run_public_statistics_differential(
        offline, subject="huge-page-bin-fresh", driver=STATISTICS_HUGE_PAGE_BIN_DRIVER,
        begin=STATISTICS_HUGE_PAGE_BIN_TRACE_BEGIN, end=STATISTICS_HUGE_PAGE_BIN_TRACE_END,
        report_name="statistics-huge-page-bin-fresh.json", stat_level=2,
        require_complete=lambda trace, description: require_statistics_huge_page_bin(
            trace, description, fresh_worker=True,
        ),
        comparison_excluded_keys=frozenset({"before.arena", "allocated.arena", "terminal.arena"}),
        driver_defines=("-DCRABC_MI_FRESH_WORKER=1",),
    )


def run_statistics_huge_page_bin_fresh_then_allocate_differential(offline: bool) -> dict[str, Any]:
    def require_followup(trace: Mapping[str, str], description: str) -> None:
        if trace.get("worker.fresh") != "1" or trace.get("worker.mapped") != "-1":
            raise harness.HarnessError(f"{description} did not free from a fresh worker")
        if trace.get("worker.followup_usable") != "8":
            raise harness.HarnessError(f"{description} did not attach on its later allocation")
        if trace.get("freed.huge_page_bin") != "1,1,0":
            raise harness.HarnessError(f"{description} retained the remotely freed huge page")

    return run_public_statistics_differential(
        offline, subject="huge-page-bin-fresh-then-allocate", driver=STATISTICS_HUGE_PAGE_BIN_DRIVER,
        begin=STATISTICS_HUGE_PAGE_BIN_TRACE_BEGIN, end=STATISTICS_HUGE_PAGE_BIN_TRACE_END,
        report_name="statistics-huge-page-bin-fresh-then-allocate.json", stat_level=2,
        require_complete=require_followup,
        comparison_excluded_keys=frozenset({"before.arena", "allocated.arena", "terminal.arena"}),
        driver_defines=("-DCRABC_MI_FRESH_WORKER=1", "-DCRABC_MI_FRESH_WORKER_ALLOCATE_AFTER_FREE=1"),
    )


def run_statistics_remote_normal_differential(offline: bool) -> dict[str, Any]:
    return run_public_statistics_differential(
        offline, subject="remote-normal", driver=STATISTICS_REMOTE_NORMAL_DRIVER,
        begin=STATISTICS_REMOTE_NORMAL_TRACE_BEGIN, end=STATISTICS_REMOTE_NORMAL_TRACE_END,
        report_name="statistics-remote-normal.json", require_complete=require_statistics_remote_normal,
    )


def run_statistics_remote_normal_fresh_differential(offline: bool) -> dict[str, Any]:
    return run_public_statistics_differential(
        offline, subject="remote-normal-fresh", driver=STATISTICS_REMOTE_NORMAL_DRIVER,
        begin=STATISTICS_REMOTE_NORMAL_TRACE_BEGIN, end=STATISTICS_REMOTE_NORMAL_TRACE_END,
        report_name="statistics-remote-normal-fresh.json", stat_level=2,
        require_complete=require_statistics_remote_normal_fresh,
        driver_defines=("-DCRABC_MI_FRESH_WORKER=1", "-DCRABC_MI_STAT_LEVEL=2",
                        "-DCRABC_MI_TARGET_REQUEST=32768",
                        "-DCRABC_MI_FRESH_WORKER_UFREE=1"),
    )


def run_statistics_remote_normal_fresh_cfree_differential(offline: bool) -> dict[str, Any]:
    return run_public_statistics_differential(
        offline, subject="remote-normal-fresh-cfree", driver=STATISTICS_REMOTE_NORMAL_DRIVER,
        begin=STATISTICS_REMOTE_NORMAL_TRACE_BEGIN, end=STATISTICS_REMOTE_NORMAL_TRACE_END,
        report_name="statistics-remote-normal-fresh-cfree.json", stat_level=2,
        require_complete=lambda trace, description: require_statistics_remote_normal_fresh(
            trace, description, checked_free=True,
        ),
        driver_defines=("-DCRABC_MI_FRESH_WORKER=1", "-DCRABC_MI_STAT_LEVEL=2",
                        "-DCRABC_MI_TARGET_REQUEST=32768",
                        "-DCRABC_MI_FRESH_WORKER_CFREE=1"),
    )


def run_statistics_remote_normal_fresh_usable_differential(offline: bool) -> dict[str, Any]:
    return run_public_statistics_differential(
        offline, subject="remote-normal-fresh-usable", driver=STATISTICS_REMOTE_NORMAL_DRIVER,
        begin=STATISTICS_REMOTE_NORMAL_TRACE_BEGIN, end=STATISTICS_REMOTE_NORMAL_TRACE_END,
        report_name="statistics-remote-normal-fresh-usable.json", stat_level=2,
        require_complete=lambda trace, description: require_statistics_remote_normal_fresh(
            trace, description, queried_usable=True,
        ),
        driver_defines=("-DCRABC_MI_FRESH_WORKER=1", "-DCRABC_MI_STAT_LEVEL=2",
                        "-DCRABC_MI_TARGET_REQUEST=32768",
                        "-DCRABC_MI_FRESH_WORKER_UFREE=1",
                        "-DCRABC_MI_FRESH_WORKER_QUERY_USABLE=1"),
    )


def run_statistics_aligned_huge_differential(offline: bool) -> dict[str, Any]:
    return run_public_statistics_differential(
        offline, subject="aligned-huge", driver=STATISTICS_ALIGNED_HUGE_DRIVER,
        begin=STATISTICS_ALIGNED_HUGE_TRACE_BEGIN, end=STATISTICS_ALIGNED_HUGE_TRACE_END,
        report_name="statistics-aligned-huge.json", require_complete=require_statistics_aligned_huge,
    )


def run_statistics_requested_production_differential(offline: bool) -> dict[str, Any]:
    return run_public_statistics_differential(
        offline, subject="requested-production", driver=STATISTICS_REQUESTED_PRODUCTION_DRIVER,
        begin=STATISTICS_REQUESTED_PRODUCTION_TRACE_BEGIN,
        end=STATISTICS_REQUESTED_PRODUCTION_TRACE_END,
        report_name="statistics-requested-production.json", stat_level=2,
        require_complete=require_statistics_requested_production,
    )


def run_statistics_fast_allocation_differential(offline: bool) -> dict[str, Any]:
    profiles = {}
    for level in (0, 1, 2):
        profiles[str(level)] = run_public_statistics_differential(
            offline, subject=f"fast-allocation-level-{level}", driver=STATISTICS_FAST_ALLOCATION_DRIVER,
            begin=STATISTICS_FAST_ALLOCATION_TRACE_BEGIN, end=STATISTICS_FAST_ALLOCATION_TRACE_END,
            report_name=f"statistics-fast-allocation-level-{level}.json", stat_level=level,
            driver_defines=(f"-DCRABC_STAT_LEVEL={level}",),
            require_complete=require_statistics_fast_allocation, retain_artifacts=True,
        )
    report = {"status": "passed", "profiles": profiles,
              "compared_key_count": sum(profile["compared_key_count"] for profile in profiles.values()),
              "provenance": {"seal": integrated.source_seal(), "git": engine.git_provenance(),
                             "driver": engine.file_record(STATISTICS_FAST_ALLOCATION_DRIVER),
                             "gate": engine.file_record(Path(__file__))}}
    harness.write_json(ARTIFACTS / "statistics-fast-allocation.json", report)
    return report


def run_statistics_remote_bin_differential(offline: bool) -> dict[str, Any]:
    # Worker setup can change the absolute mmap count. Keep those raw images
    # and require no arena or OS-mapping growth within the medium transition.
    return run_public_statistics_differential(
        offline, subject="remote-bin", driver=STATISTICS_REMOTE_BIN_DRIVER,
        begin=STATISTICS_REMOTE_BIN_TRACE_BEGIN, end=STATISTICS_REMOTE_BIN_TRACE_END,
        report_name="statistics-remote-bin.json", stat_level=2,
        require_complete=require_statistics_remote_bin,
        comparison_excluded_keys=frozenset({"medium.before.arena", "medium.allocated.arena",
                                            "medium.terminal.arena"}),
    )


def run_adapter_differential(
    offline: bool, *, driver: Path = ADAPTER_DRIVER, begin: str = ADAPTER_TRACE_BEGIN,
    end: str = ADAPTER_TRACE_END, report_name: str = "adapter.json",
) -> dict[str, Any]:
    """Link one shared M7 driver against pinned C and the native adapter.

    The M4 gate owns the adapter build; this reuses its C and adapter link
    steps with an M7 driver in place of the M4 one.
    """

    import x86_64_m4_gate as m4

    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    with harness.temporary_directory("crabc-mimalloc-x86_64-m7-adapter-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        c_driver = temporary / "m7-adapter-c"
        build = harness.command_record(
            [
                compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                *harness.CONFIGURATION_PROFILES["release"], "-I", str(source / "include"),
                str(driver), str(source / "src/static.c"), "-pthread", "-o", str(c_driver),
            ],
            cwd=source,
        )
        harness.require_success(build, "M7 adapter C driver build")
        library = m4.build_adapter_library(temporary)
        rust_driver = temporary / "m7-adapter-rust"
        link = harness.command_record(
            [
                compiler, "-std=c11", "-O2", "-I", str(source / "include"),
                str(driver), str(library), "-pthread", "-o", str(rust_driver),
            ],
            cwd=source,
        )
        harness.require_success(link, "M7 adapter Rust driver link")
        executions = {
            side: harness.command_record((str(driver),), cwd=temporary, env={}, timeout_seconds=600)
            for side, driver in (("c", c_driver), ("rust", rust_driver))
        }
    for side, execution in executions.items():
        harness.require_success(execution, f"M7 adapter {side} driver")
    traces = {
        side: parse_options_trace(str(execution["stdout"]), f"{side} M7 adapter trace", begin, end)
        for side, execution in executions.items()
    }
    compare_options_traces(traces["c"], traces["rust"])
    report = {"compared_key_count": len(traces["c"]), "status": "passed", "trace": traces["c"]}
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    harness.write_json(ARTIFACTS / report_name, report)
    return report


def run_error_sites_differential(offline: bool) -> dict[str, Any]:
    return run_trace_differential(
        offline, subject="error-sites", oracle=ERROR_SITES_ORACLE, test=ERROR_SITES_RUST_TEST,
        begin=ERROR_SITES_TRACE_BEGIN, end=ERROR_SITES_TRACE_END,
        require_complete=require_complete_error_sites_trace, report_name="error-sites.json",
        integration_test=True, environment=ERROR_SITES_ENVIRONMENT,
        c_stderr_record=("error_site.startup.messages", startup_record_from_stderr),
    )


def run_option_profiles_differential(offline: bool) -> dict[str, Any]:
    compared = 0
    profiles: dict[str, Any] = {}
    for profile, environment in OPTION_PROFILES.items():
        report = run_trace_differential(
            offline, subject=f"option-profile-{profile}", oracle=OPTION_PROFILES_ORACLE,
            test=OPTION_PROFILES_RUST_TEST, begin=OPTION_PROFILES_TRACE_BEGIN, end=OPTION_PROFILES_TRACE_END,
            require_complete=require_complete_option_profile_trace,
            report_name=f"option-profile-{profile}.json", integration_test=True, environment=environment,
        )
        compared += report["compared_key_count"]
        profiles[profile] = {"environment": environment, "trace": report["trace"]}
    summary = {"compared_key_count": compared, "profiles": profiles, "status": "passed"}
    harness.write_json(ARTIFACTS / "option-profiles.json", summary)
    return summary


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
    mode.add_argument("--delayed-output-saturation-differential", action="store_true",
        help="compare the pinned-C/Rust delayed output cap and custom callback transition")
    mode.add_argument("--show-errors-profile-differential", action="store_true",
        help="run the pinned-C/Rust MI_SHOW_ERRORS options and diagnostics differential")
    mode.add_argument("--option-effects-differential", action="store_true",
        help="run the pinned-C/Rust option-effects differential")
    mode.add_argument("--destroy-on-exit-differential", action="store_true",
        help="run the pinned-C/Rust process-done option-effects differential")
    mode.add_argument("--page-max-candidates-differential", action="store_true",
        help="run the pinned-C/Rust bounded page candidate differential")
    mode.add_argument("--thread-init-differential", action="store_true",
        help="run the shared-driver pinned-C/native-adapter thread-initialization failure differential")
    mode.add_argument("--page-map-differential", action="store_true",
        help="run the shared-driver pinned-C/native-adapter startup page-map failure differential")
    mode.add_argument("--statistics-differential", action="store_true",
        help="run the shared-driver pinned-C/native-adapter statistics differential")
    mode.add_argument("--statistics-level-one-differential", action="store_true",
        help="run the pinned-C/native-adapter level-one statistics differential")
    mode.add_argument("--statistics-level-one-output-merge-differential", action="store_true",
        help="run the pinned-C/Rust level-one final-output merge differential")
    mode.add_argument("--statistics-level-two-requested-differential", action="store_true",
        help="run the pinned-C/Rust level-two requested-size final-output differential")
    mode.add_argument("--statistics-level-two-bins-differential", action="store_true",
        help="run the pinned-C/Rust level-two nonzero-bin final-output differential")
    mode.add_argument("--statistics-level-two-page-huge-differential", action="store_true",
        help="run the pinned-C/Rust level-two huge/page final-output differential")
    mode.add_argument("--statistics-json-differential", action="store_true",
        help="compare pinned-C/Rust public JSON buffer behavior under each statistics profile")
    mode.add_argument("--statistics-page-extend-differential", action="store_true",
        help="compare pinned-C/Rust page extension statistics under MI_STAT=1")
    mode.add_argument("--statistics-page-second-extension-differential", action="store_true",
        help="compare second and third regular-page extension statistics under MI_STAT=1")
    mode.add_argument("--statistics-huge-differential", action="store_true",
        help="compare pinned-C/Rust huge allocation statistics under MI_STAT=1")
    mode.add_argument("--statistics-huge-page-bin-differential", action="store_true",
        help="compare pinned-C/Rust arena huge page-bin statistics under MI_STAT=2")
    mode.add_argument("--statistics-huge-page-bin-fresh-differential", action="store_true",
        help="compare a fresh worker's metadata-Theap huge free under MI_STAT=2")
    mode.add_argument("--statistics-huge-page-bin-fresh-then-allocate-differential", action="store_true",
        help="compare a fresh worker's huge free followed by its first allocation")
    mode.add_argument("--statistics-remote-normal-differential", action="store_true",
        help="compare pinned-C/Rust cross-thread normal free statistics under MI_STAT=1")
    mode.add_argument("--statistics-remote-normal-fresh-differential", action="store_true",
        help="compare a fresh worker's cross-thread medium ufree under MI_STAT=2")
    mode.add_argument("--statistics-remote-normal-fresh-cfree-differential", action="store_true",
        help="compare a fresh worker's checked cross-thread medium free under MI_STAT=2")
    mode.add_argument("--statistics-remote-normal-fresh-usable-differential", action="store_true",
        help="compare a fresh worker's usable-size query before cross-thread medium free")
    mode.add_argument("--statistics-aligned-huge-differential", action="store_true",
        help="compare pinned-C/Rust OS-aligned huge statistics under MI_STAT=1")
    mode.add_argument("--statistics-requested-production-differential", action="store_true",
        help="compare pinned-C/Rust ordinary and OS-aligned requested-size producers under MI_STAT=2")
    mode.add_argument("--statistics-fast-allocation-differential", action="store_true",
        help="compare pinned-C/Rust local normal-bin allocation lifetimes under MI_STAT=0, 1, and 2")
    mode.add_argument("--statistics-remote-bin-differential", action="store_true",
        help="compare pinned-C/Rust freeing-Theap size-bin attribution under MI_STAT=2")
    mode.add_argument("--adapter-differential", action="store_true",
        help="run the shared-driver pinned-C/native-adapter M7 differential")
    mode.add_argument("--option-profiles-differential", action="store_true",
        help="run the pinned-C/Rust per-environment option-profile differential")
    mode.add_argument("--error-sites-differential", action="store_true",
        help="run the pinned-C/Rust `_mi_error_message` site differential")
    mode.add_argument("--default-baseline-audit", action="store_true",
        help="build and inspect the default native allocator release artifact")
    mode.add_argument("--optional-isa-differential", action="store_true",
        help="compare scalar, arch-only, and AVX2 bitmap allocation paths with pinned C")
    parser.add_argument("--offline", action="store_true", help="require the verified archive in the local cache")
    parser.add_argument("--scratch", type=Path, help="fresh output directory for the default baseline audit")
    arguments = parser.parse_args(argv)
    if arguments.optional_isa_differential:
        report = run_optional_isa_differential(arguments.offline)
        print(f"M7 optional ISA differential passed: {report['compared_key_count']} keys in {len(report['profiles'])} modes")
        return 0
    if arguments.options_differential:
        report = run_options_differential(arguments.offline)
        print(f"M7 options/environment differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.delayed_output_saturation_differential:
        report = run_delayed_output_saturation_differential(arguments.offline)
        print(f"M7 delayed output saturation differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.show_errors_profile_differential:
        report = run_show_errors_profile_differential(arguments.offline)
        print(f"M7 MI_SHOW_ERRORS differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.thread_init_differential:
        report = run_adapter_differential(
            arguments.offline, driver=THREAD_INIT_DRIVER, begin=THREAD_INIT_TRACE_BEGIN,
            end=THREAD_INIT_TRACE_END, report_name="thread-init.json",
        )
        print(f"M7 thread-initialization differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.page_map_differential:
        report = run_adapter_differential(
            arguments.offline, driver=PAGE_MAP_DRIVER, begin=PAGE_MAP_TRACE_BEGIN,
            end=PAGE_MAP_TRACE_END, report_name="page-map.json",
        )
        print(f"M7 startup page-map differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.statistics_differential:
        report = run_adapter_differential(
            arguments.offline, driver=STATISTICS_DRIVER, begin=STATISTICS_TRACE_BEGIN,
            end=STATISTICS_TRACE_END, report_name="statistics.json",
        )
        print(f"M7 statistics differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.statistics_level_one_differential:
        report = run_statistics_level_one_differential(arguments.offline)
        print(f"M7 level-one statistics differential passed: {len(report['trace'])} keys")
        print(f"pinned C: {json.dumps(report['c_trace'], sort_keys=True)}")
        print(f"Rust: {json.dumps(report['rust_trace'], sort_keys=True)}")
        return 0
    if arguments.statistics_level_one_output_merge_differential:
        report = run_statistics_level_one_output_merge_differential(arguments.offline)
        print(f"M7 level-one output merge differential passed: {report['compared_key_count']} keys")
        print(json.dumps(report["trace"], sort_keys=True))
        return 0
    if arguments.statistics_level_two_requested_differential:
        report = run_statistics_level_two_requested_differential(arguments.offline)
        print(f"M7 level-two requested differential passed: {report['compared_key_count']} keys")
        print(json.dumps(report["trace"], sort_keys=True))
        return 0
    if arguments.statistics_level_two_bins_differential:
        report = run_statistics_level_two_bins_differential(arguments.offline)
        print(f"M7 level-two bins differential passed: {report['compared_key_count']} keys")
        print(json.dumps(report["trace"], sort_keys=True))
        return 0
    if arguments.statistics_level_two_page_huge_differential:
        report = run_statistics_level_two_page_huge_differential(arguments.offline)
        print(f"M7 level-two huge/page differential passed: {report['compared_key_count']} keys")
        print(json.dumps(report["trace"], sort_keys=True))
        return 0
    if arguments.statistics_json_differential:
        report = run_statistics_json_differential(arguments.offline)
        print(f"M7 statistics JSON differential passed: {report['compared_key_count']} keys "
              f"in {len(report['profiles'])} profiles")
        return 0
    if arguments.statistics_page_extend_differential:
        report = run_statistics_page_extend_differential(arguments.offline)
        print(f"M7 page-extension statistics differential passed: {len(report['c_trace'])} keys")
        return 0
    if arguments.statistics_page_second_extension_differential:
        report = run_statistics_page_second_extension_differential(arguments.offline)
        print(f"M7 repeated page-extension statistics differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.statistics_huge_differential:
        report = run_statistics_huge_differential(arguments.offline)
        print(f"M7 huge statistics differential passed: {len(report['c_trace'])} keys")
        return 0
    if arguments.statistics_huge_page_bin_differential:
        report = run_statistics_huge_page_bin_differential(arguments.offline)
        print(f"M7 huge page-bin statistics differential passed: {report['compared_key_count']} compared keys")
        return 0
    if arguments.statistics_huge_page_bin_fresh_differential:
        report = run_statistics_huge_page_bin_fresh_differential(arguments.offline)
        print(f"M7 fresh-worker huge statistics differential passed: {report['compared_key_count']} compared keys")
        return 0
    if arguments.statistics_huge_page_bin_fresh_then_allocate_differential:
        report = run_statistics_huge_page_bin_fresh_then_allocate_differential(arguments.offline)
        print(f"M7 fresh-worker free-then-allocate differential passed: {report['compared_key_count']} compared keys")
        return 0
    if arguments.statistics_remote_normal_differential:
        report = run_statistics_remote_normal_differential(arguments.offline)
        print(f"M7 remote normal statistics differential passed: {len(report['c_trace'])} keys")
        return 0
    if arguments.statistics_remote_normal_fresh_differential:
        report = run_statistics_remote_normal_fresh_differential(arguments.offline)
        print(f"M7 fresh-worker remote normal statistics differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.statistics_remote_normal_fresh_cfree_differential:
        report = run_statistics_remote_normal_fresh_cfree_differential(arguments.offline)
        print(f"M7 fresh-worker checked free statistics differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.statistics_remote_normal_fresh_usable_differential:
        report = run_statistics_remote_normal_fresh_usable_differential(arguments.offline)
        print(f"M7 fresh-worker usable-size-before-free differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.statistics_aligned_huge_differential:
        report = run_statistics_aligned_huge_differential(arguments.offline)
        print(f"M7 aligned huge statistics differential passed: {len(report['c_trace'])} keys")
        return 0
    if arguments.statistics_requested_production_differential:
        report = run_statistics_requested_production_differential(arguments.offline)
        print(f"M7 requested-size production differential passed: {len(report['c_trace'])} keys")
        return 0
    if arguments.statistics_fast_allocation_differential:
        report = run_statistics_fast_allocation_differential(arguments.offline)
        print(f"M7 fast allocation statistics differential passed: {report['compared_key_count']} keys in {len(report['profiles'])} modes")
        return 0
    if arguments.statistics_remote_bin_differential:
        report = run_statistics_remote_bin_differential(arguments.offline)
        print(f"M7 remote bin statistics differential passed: {report['compared_key_count']} compared keys")
        return 0
    if arguments.adapter_differential:
        report = run_adapter_differential(arguments.offline)
        print(f"M7 adapter differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.option_profiles_differential:
        report = run_option_profiles_differential(arguments.offline)
        print(f"M7 option-profile differential passed: {report['compared_key_count']} keys "
              f"in {len(report['profiles'])} profiles")
        return 0
    if arguments.error_sites_differential:
        report = run_error_sites_differential(arguments.offline)
        print(f"M7 error-site differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.option_effects_differential:
        report = run_option_effects_differential(arguments.offline)
        print(f"M7 option-effects differential passed: {report['compared_key_count']} keys")
        return 0
    if arguments.destroy_on_exit_differential:
        report = run_destroy_on_exit_differential(arguments.offline)
        print(f"M7 destroy-on-exit differential passed: {len(report['modes'])} modes")
        return 0
    if arguments.page_max_candidates_differential:
        report = run_page_max_candidates_differential(arguments.offline)
        print(f"M7 page-max-candidates differential passed: {len(report['modes'])} limits")
        return 0
    if arguments.default_baseline_audit:
        if arguments.scratch is None:
            parser.error("--default-baseline-audit requires --scratch")
        report = run_default_baseline_audit(arguments.offline, arguments.scratch)
        print(f"M7 default baseline audit passed: {report['artifact']['artifact_sha256']}")
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
    report["provenance"] = {
        "seal": {**integrated.source_seal(), "gate": engine.file_record(Path(__file__)),
                 "contract": engine.file_record(CONTRACT)},
        "git": engine.git_provenance(),
        "evidence": {name: engine.file_record(harness.ROOT / record["log"])
                     for name, record in report["evidence"].items()},
    }
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
