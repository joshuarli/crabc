#!/usr/bin/env python3
"""Evaluate the native-mimalloc architecture ratchet without promotion claims.

The current native allocator is a bounded ``native-mimalloc-shadow`` route.
This evaluator records that fact from the selected source/module graph and its
checked-in workload contracts.  Static inspection is deliberately useful only
as a negative architecture witness: it can show that known scaffolding is
still selected, but it cannot prove that a hot path has no operation.  A final
gate therefore also requires an independently generated runtime/artifact
evidence record with production-general-or-better scope.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "compat/allocator/architecture-gate-v3.5.0.json"
DEFAULT_REPORT = ROOT / "target/architecture-ratchet/latest.json"
RUNTIME_EVIDENCE_SCHEMA = "crabc-mimalloc-architecture-runtime-evidence"


class RatchetError(RuntimeError):
    """A checked-in architecture contract or supplied evidence is invalid."""


@dataclass(frozen=True)
class SourceMatch:
    path: str
    line: int
    pattern: str

    def as_dict(self) -> dict[str, object]:
        return {"line": self.line, "path": self.path, "pattern": self.pattern}


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RatchetError(f"required architecture input is absent: {path}") from error
    except json.JSONDecodeError as error:
        raise RatchetError(f"invalid JSON in {path}: {error}") from error
    if not isinstance(value, dict):
        raise RatchetError(f"architecture JSON root is not an object: {path}")
    return value


def sha256(path: Path) -> str:
    if not path.is_file():
        raise RatchetError(f"required architecture input is absent: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strip_rust_comments(source: str) -> str:
    """Mask comments while preserving line numbers for simple source anchors.

    The ratchet intentionally does not pretend to be a Rust parser.  It does
    need to avoid treating an explanatory comment as compiled scaffolding, so
    it removes line and nested block comments before applying deliberately
    narrow declaration/call-site patterns.
    """

    result: list[str] = []
    index = 0
    block_depth = 0
    in_line_comment = False
    in_string: str | None = None
    escaped = False
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if in_line_comment:
            if character == "\n":
                in_line_comment = False
                result.append("\n")
            else:
                result.append(" ")
            index += 1
            continue
        if block_depth:
            if character == "/" and following == "*":
                block_depth += 1
                result.extend((" ", " "))
                index += 2
            elif character == "*" and following == "/":
                block_depth -= 1
                result.extend((" ", " "))
                index += 2
            else:
                result.append("\n" if character == "\n" else " ")
                index += 1
            continue
        if in_string is not None:
            result.append("\n" if character == "\n" else " ")
            if not escaped and character == in_string:
                in_string = None
            escaped = not escaped and character == "\\"
            if character != "\\":
                escaped = False
            index += 1
            continue
        if character == "/" and following == "/":
            in_line_comment = True
            result.extend((" ", " "))
            index += 2
        elif character == "/" and following == "*":
            block_depth = 1
            result.extend((" ", " "))
            index += 2
        # Rust lifetimes use an apostrophe (`'main`), so treating every
        # apostrophe as a character literal would hide large portions of the
        # selected source. The declaration/call patterns below do not match
        # character literals; masking only ordinary strings is sufficient to
        # keep diagnostics out of this lightweight source inspection.
        elif character == '"':
            in_string = character
            result.append(" ")
            index += 1
        else:
            result.append(character)
            index += 1
    return "".join(result)


def source_matches(root: Path, relative_path: str, pattern: str) -> list[SourceMatch]:
    path = root / relative_path
    if not path.is_file():
        raise RatchetError(f"selected production source is absent: {relative_path}")
    source = strip_rust_comments(path.read_text(encoding="utf-8"))
    matches: list[SourceMatch] = []
    for match in re.finditer(pattern, source, flags=re.MULTILINE):
        matches.append(
            SourceMatch(
                path=relative_path,
                line=source.count("\n", 0, match.start()) + 1,
                pattern=pattern,
            )
        )
    return matches


def rust_function_body(source: str, function: str) -> tuple[int, str, str]:
    """Return one Rust function body's offset plus raw and comment-masked bodies.

    This intentionally recognizes only the narrow free-dispatch boundary
    named by the manifest.  It is not a general Rust parser; the brace walk
    gives this ratchet a structural boundary stronger than a repository-wide
    grep, while comments and ordinary strings cannot supply a false branch.
    """

    code = strip_rust_comments(source)
    header = re.compile(
        rf"\b(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?fn\s+{re.escape(function)}\b[^{{]*\{{",
        re.MULTILINE,
    )
    match = header.search(code)
    if match is None:
        raise RatchetError(f"selected source does not define required function: {function}")
    opening_brace = code.find("{", match.start(), match.end())
    depth = 0
    for index in range(opening_brace, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return (
                    opening_brace + 1,
                    source[opening_brace + 1 : index],
                    code[opening_brace + 1 : index],
                )
    raise RatchetError(f"selected function has an unclosed body: {function}")


def function_matches(
    root: Path, relative_path: str, function: str, pattern: str
) -> list[SourceMatch]:
    return [
        source_match
        for _, source_match in function_match_offsets(root, relative_path, function, pattern)
    ]


def function_match_offsets(
    root: Path, relative_path: str, function: str, pattern: str
) -> list[tuple[int, SourceMatch]]:
    path = root / relative_path
    if not path.is_file():
        raise RatchetError(f"selected production source is absent: {relative_path}")
    source = path.read_text(encoding="utf-8")
    body_offset, _, body = rust_function_body(source, function)
    return [
        (
            match.start(),
            SourceMatch(
                path=relative_path,
                line=source.count("\n", 0, body_offset + match.start()) + 1,
                pattern=pattern,
            ),
        )
        for match in re.finditer(pattern, body, flags=re.MULTILINE)
    ]


def function_literal_match_offsets(
    root: Path, relative_path: str, function: str, literal: str
) -> list[tuple[int, SourceMatch]]:
    """Find literal documentation markers in the selected function body only."""

    path = root / relative_path
    if not path.is_file():
        raise RatchetError(f"selected production source is absent: {relative_path}")
    source = path.read_text(encoding="utf-8")
    body_offset, raw_body, _ = rust_function_body(source, function)
    matches: list[tuple[int, SourceMatch]] = []
    start = 0
    while True:
        offset = raw_body.find(literal, start)
        if offset < 0:
            return matches
        matches.append(
            (
                offset,
                SourceMatch(
                    path=relative_path,
                    line=source.count("\n", 0, body_offset + offset) + 1,
                    pattern=literal,
                ),
            )
        )
        start = offset + len(literal)


def required_mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RatchetError(f"architecture manifest {name} must be an object")
    return value


def required_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise RatchetError(f"architecture manifest {name} must be a non-empty string")
    return value


def validate_manifest(manifest: Mapping[str, Any]) -> None:
    if manifest.get("format") != 1:
        raise RatchetError("unsupported architecture gate format")
    if manifest.get("schema") != "crabc-mimalloc-architecture-gate":
        raise RatchetError("unsupported architecture gate schema")
    selected = required_mapping(manifest.get("selected_production"), "selected_production")
    required_string(selected.get("feature"), "selected_production.feature")
    sources = selected.get("sources")
    if not isinstance(sources, list) or not all(isinstance(path, str) for path in sources):
        raise RatchetError("architecture manifest selected_production.sources must be string paths")
    scope = required_mapping(manifest.get("scope"), "scope")
    if scope.get("current") not in {
        "bounded_witness",
        "direct_engine",
        "shadow_subset",
        "production_general",
        "promotion_qualified",
    }:
        raise RatchetError("architecture manifest scope.current is not an evidence scope")
    if scope.get("static_analysis_cannot_close_final_gate") is not True:
        raise RatchetError("architecture manifest must prohibit static-only final success")
    caller_dispatch = required_mapping(
        manifest.get("caller_identity_first_free_dispatch"),
        "caller_identity_first_free_dispatch",
    )
    required_string(caller_dispatch.get("path"), "caller_identity_first_free_dispatch.path")
    required_string(caller_dispatch.get("function"), "caller_identity_first_free_dispatch.function")
    for name in ("caller_identity_patterns", "pointer_dispatch_patterns"):
        patterns = caller_dispatch.get(name)
        if not isinstance(patterns, list) or not patterns or not all(
            isinstance(pattern, str) and pattern for pattern in patterns
        ):
            raise RatchetError(f"architecture manifest caller-identity dispatch {name} is invalid")
    maximum_identity_matches = caller_dispatch.get("maximum_phase_a_identity_matches")
    if maximum_identity_matches != 1:
        raise RatchetError("architecture manifest Phase-A bridge must permit its sole identity branch")
    phase_a_bridge = required_mapping(
        caller_dispatch.get("phase_a_bridge"),
        "caller_identity_first_free_dispatch.phase_a_bridge",
    )
    if phase_a_bridge.get("phase") != "A" or phase_a_bridge.get("final_acceptance") is not False:
        raise RatchetError("caller-identity bridge must be a non-final Phase-A exception")
    for name in ("marker", "removal_condition", "source_anchor_pattern"):
        required_string(phase_a_bridge.get(name), f"caller_identity_first_free_dispatch.phase_a_bridge.{name}")
    metrics = required_mapping(manifest.get("metrics"), "metrics")
    required_metrics = {
        "local_hot_path_process_scheduler_ops",
        "local_hot_path_global_pagemap_leases",
        "local_operation_owner_registry_scans",
        "local_operation_client_ledger_scans",
        "remote_free_owner_registry_scans",
        "extra_control_bytes_per_live_allocation",
        "per_call_engine_park_resume",
        "exited_owner_admission_survives_thread_exit",
        "single_thread_throughput_ratio",
        "four_thread_local_throughput_ratio",
        "cross_thread_free_throughput_ratio",
        "metadata_plateau_after_warmup",
    }
    missing_metrics = sorted(required_metrics - set(metrics))
    if missing_metrics:
        raise RatchetError("architecture manifest is missing metrics: " + ", ".join(missing_metrics))
    for name in required_metrics:
        metric = required_mapping(metrics[name], f"metrics.{name}")
        if "final_required" not in metric:
            raise RatchetError(f"architecture manifest metrics.{name}.final_required is absent")
    forbidden = required_mapping(manifest.get("forbidden_scaffolding"), "forbidden_scaffolding")
    patterns = forbidden.get("patterns")
    if not isinstance(patterns, Mapping) or not patterns:
        raise RatchetError("architecture manifest forbidden_scaffolding.patterns is empty")
    for name, rule in patterns.items():
        if not isinstance(name, str):
            raise RatchetError("architecture manifest forbidden scaffolding name is invalid")
        rule_mapping = required_mapping(rule, f"forbidden_scaffolding.patterns.{name}")
        required_string(rule_mapping.get("path"), f"forbidden_scaffolding.patterns.{name}.path")
        required_string(rule_mapping.get("pattern"), f"forbidden_scaffolding.patterns.{name}.pattern")
    baseline = required_mapping(manifest.get("ratchet_baseline"), "ratchet_baseline")
    static_ceiling = required_mapping(baseline.get("static_signal_ceiling"), "ratchet_baseline.static_signal_ceiling")
    if set(static_ceiling) != required_metrics:
        raise RatchetError("architecture manifest ratchet baseline must cover every static metric")
    if not all(type(value) is int and value >= 0 for value in static_ceiling.values()):
        raise RatchetError("architecture manifest static signal ceilings must be non-negative integers")


def collect_static_signals(root: Path, manifest: Mapping[str, Any]) -> dict[str, list[SourceMatch]]:
    """Collect source indicators, never a claimed dynamic operation count."""

    selected = required_mapping(manifest["selected_production"], "selected_production")
    runtime = required_string(selected.get("runtime_source"), "selected_production.runtime_source")
    page_map = required_string(selected.get("page_map_source"), "selected_production.page_map_source")
    signals = {
        "local_hot_path_process_scheduler_ops": [
            *source_matches(root, runtime, r"\bpage_owner_state\s*:\s*AtomicUsize\b"),
            *source_matches(root, runtime, r"\.page_owner_state\s*\.compare_exchange(?:_weak)?\s*\("),
        ],
        "local_hot_path_global_pagemap_leases": [
            *source_matches(root, runtime, r"\bProcessPageMapLease\b"),
            *source_matches(root, page_map, r"\bstruct\s+ProcessPageMapMutationLease\b"),
        ],
        "local_operation_owner_registry_scans": [
            *source_matches(root, runtime, r"\bfn\s+claim_current_slot(?:_excluding_held_route)?\s*\("),
            *source_matches(root, runtime, r"\bwhile\s*!current\.is_null\(\)\s*\{"),
        ],
        "local_operation_client_ledger_scans": [
            *source_matches(root, runtime, r"\bstruct\s+PreparedOwnerExitClients\b"),
            *source_matches(root, runtime, r"\bfor\s+slot\s+in\s+0\.\.self\.slot_count\(\)\s*\{"),
            *source_matches(root, runtime, r"\bsession\.clients\.native_client_for_block\s*\("),
        ],
        "remote_free_owner_registry_scans": [
            *source_matches(root, runtime, r"\bfn\s+claim_exact_client\s*\("),
            *source_matches(root, runtime, r"\bfn\s+usable_size_exact\s*\("),
            *source_matches(root, runtime, r"\bwhile\s*!current\.is_null\(\)\s*\{"),
        ],
        "extra_control_bytes_per_live_allocation": [
            *source_matches(root, runtime, r"\bstruct\s+PreparedOwnerExitClient\b"),
            *source_matches(root, runtime, r"\benum\s+DetachedOwnerExitClientLedger\b"),
        ],
        "per_call_engine_park_resume": [
            *source_matches(root, runtime, r"\bfn\s+suspend\s*\("),
            *source_matches(root, runtime, r"\bfn\s+resume\s*<"),
            *source_matches(root, runtime, r"\.suspend\(\)"),
            *source_matches(root, runtime, r"\.resume\("),
        ],
        "exited_owner_admission_survives_thread_exit": [
            *source_matches(root, runtime, r"\bstruct\s+LaterThreadAdmissionClaim\b"),
            *source_matches(root, runtime, r"\badmission\s*:\s*LaterThreadAdmissionClaim\b"),
        ],
        # Throughput and metadata plateau are runtime measurements. Keeping
        # their source signal sets empty records that source inspection has no
        # legitimate value to claim for either field.
        "single_thread_throughput_ratio": [],
        "four_thread_local_throughput_ratio": [],
        "cross_thread_free_throughput_ratio": [],
        "metadata_plateau_after_warmup": [],
    }
    return {name: sorted(matches, key=lambda item: (item.path, item.line, item.pattern)) for name, matches in signals.items()}


def caller_identity_first_free_dispatch(
    root: Path, manifest: Mapping[str, Any]
) -> dict[str, object]:
    """Classify `native_free` dispatch without treating a bridge as final acceptance."""

    policy = required_mapping(
        manifest["caller_identity_first_free_dispatch"],
        "caller_identity_first_free_dispatch",
    )
    path = required_string(policy.get("path"), "caller_identity_first_free_dispatch.path")
    function = required_string(policy.get("function"), "caller_identity_first_free_dispatch.function")
    identity_matches_with_offsets = sorted(
        (
            match
            for pattern in policy["caller_identity_patterns"]
            for match in function_match_offsets(root, path, function, pattern)
        ),
        key=lambda item: item[0],
    )
    pointer_matches_with_offsets = sorted(
        (
            match
            for pattern in policy["pointer_dispatch_patterns"]
            for match in function_match_offsets(root, path, function, pattern)
        ),
        key=lambda item: item[0],
    )
    caller_identity_first = bool(identity_matches_with_offsets) and (
        not pointer_matches_with_offsets
        or identity_matches_with_offsets[0][0] < pointer_matches_with_offsets[0][0]
    )
    identity_matches = [match for _, match in identity_matches_with_offsets]
    pointer_matches = [match for _, match in pointer_matches_with_offsets]
    bridge = required_mapping(
        policy["phase_a_bridge"],
        "caller_identity_first_free_dispatch.phase_a_bridge",
    )
    marker = required_string(
        bridge.get("marker"),
        "caller_identity_first_free_dispatch.phase_a_bridge.marker",
    )
    marker_matches_with_offsets = function_literal_match_offsets(root, path, function, marker)
    marker_matches = [match for _, match in marker_matches_with_offsets]
    marker_matches_before_or_at_identity = [
        match
        for offset, match in marker_matches_with_offsets
        if identity_matches_with_offsets and offset <= identity_matches_with_offsets[0][0]
    ]
    bridge_anchor_matches = function_matches(
        root,
        path,
        function,
        required_string(
            bridge.get("source_anchor_pattern"),
            "caller_identity_first_free_dispatch.phase_a_bridge.source_anchor_pattern",
        ),
    )
    bridge_active = (
        caller_identity_first
        and len(identity_matches) == policy["maximum_phase_a_identity_matches"]
        and bool(bridge_anchor_matches)
        and bool(marker_matches_before_or_at_identity)
    )
    if bridge_active:
        status = "phase_a_bridge"
        structural_violation = False
    elif caller_identity_first:
        status = "forbidden"
        structural_violation = True
    elif pointer_matches:
        status = "pointer_dispatch_first"
        structural_violation = False
    else:
        status = "no_caller_identity_dispatch"
        structural_violation = False
    return {
        "caller_identity_first": caller_identity_first,
        "caller_identity_matches": [match.as_dict() for match in identity_matches],
        "final_acceptance": False,
        "function": function,
        "phase_a_bridge": {
            "active": bridge_active,
            "marker": marker,
            "marker_matches": [match.as_dict() for match in marker_matches],
            "marker_matches_before_or_at_identity": [
                match.as_dict() for match in marker_matches_before_or_at_identity
            ],
            "phase": bridge["phase"],
            "removal_condition": bridge["removal_condition"],
            "source_anchor_matches": [match.as_dict() for match in bridge_anchor_matches],
        },
        "pointer_dispatch_matches": [match.as_dict() for match in pointer_matches],
        "status": status,
        "structural_violation": structural_violation,
        "warning": (
            "A Phase-A bridge is only a documented temporary exception. It cannot close the "
            "architecture gate and must be removed when pointer-to-page abandoned-state dispatch lands."
        ),
    }


def selected_source_metadata(root: Path, manifest: Mapping[str, Any]) -> dict[str, object]:
    selected = required_mapping(manifest["selected_production"], "selected_production")
    sources = [required_string(path, "selected_production.sources[]") for path in selected["sources"]]
    source_hashes = {path: sha256(root / path) for path in sources}
    libc_manifest = required_string(selected.get("libc_manifest"), "selected_production.libc_manifest")
    cargo_manifest = tomllib.loads((root / libc_manifest).read_text(encoding="utf-8"))
    cargo_features = cargo_manifest.get("features")
    cargo_targets = cargo_manifest.get("target")
    if not isinstance(cargo_features, Mapping) or not isinstance(cargo_targets, Mapping):
        raise RatchetError("selected libc Cargo manifest has no feature/target dependency metadata")
    c_abi = required_string(selected.get("c_abi_source"), "selected_production.c_abi_source")
    native_boundary = required_string(selected.get("native_boundary_source"), "selected_production.native_boundary_source")
    # Keep the include string intact here. The cfg/include pair is selected
    # source metadata, not a generic scaffold-name search.
    c_abi_source = (root / c_abi).read_text(encoding="utf-8")
    feature = required_string(selected.get("feature"), "selected_production.feature")
    feature_declared = feature in cargo_features
    target_dependencies: set[str] = set()
    for target in cargo_targets.values():
        if not isinstance(target, Mapping):
            continue
        dependencies = target.get("dependencies")
        if isinstance(dependencies, Mapping):
            target_dependencies.update(name for name in dependencies if isinstance(name, str))
    native_engine_dependency_declared = "crabc-mimalloc" in target_dependencies
    c_oracle_dependency_declared = "libmimalloc-sys" in target_dependencies
    include_pattern = rf'#\[cfg\(feature\s*=\s*"{re.escape(feature)}"\)\]\s*include!\("{re.escape(Path(native_boundary).name)}"\)'
    native_boundary_selected = bool(re.search(include_pattern, c_abi_source, flags=re.MULTILINE))
    engine_root = required_string(selected.get("engine_root_source"), "selected_production.engine_root_source")
    engine_source = strip_rust_comments((root / engine_root).read_text(encoding="utf-8"))
    runtime_selected = bool(re.search(r"\bmod\s+runtime_lifecycle\s*;", engine_source))
    return {
        "feature": feature,
        "kind": "selected-source-and-manifest-metadata",
        "libc_manifest": {
            "c_oracle_dependency_declared": c_oracle_dependency_declared,
            "feature_declared": feature_declared,
            "native_engine_dependency_declared": native_engine_dependency_declared,
            "path": libc_manifest,
            "sha256": sha256(root / libc_manifest),
        },
        "native_boundary_selected_by_feature": native_boundary_selected,
        "runtime_module_selected_unconditionally": runtime_selected,
        "sources": source_hashes,
        "status": (
            "static-selection-confirmed"
            if feature_declared and native_engine_dependency_declared and native_boundary_selected and runtime_selected
            else "selection-broken"
        ),
        "warning": (
            "This is source/module metadata, not an ELF or runtime proof. "
            "A final gate requires separately supplied runtime/artifact evidence."
        ),
    }


def collect_forbidden_scaffolding(root: Path, manifest: Mapping[str, Any]) -> dict[str, object]:
    forbidden = required_mapping(manifest["forbidden_scaffolding"], "forbidden_scaffolding")
    found: dict[str, list[dict[str, object]]] = {}
    for name, raw_rule in required_mapping(forbidden["patterns"], "forbidden_scaffolding.patterns").items():
        rule = required_mapping(raw_rule, f"forbidden_scaffolding.patterns.{name}")
        matches = source_matches(
            root,
            required_string(rule.get("path"), f"forbidden_scaffolding.patterns.{name}.path"),
            required_string(rule.get("pattern"), f"forbidden_scaffolding.patterns.{name}.pattern"),
        )
        if matches:
            found[name] = [match.as_dict() for match in matches]
    return {
        "compiled_from_selected_source": bool(found),
        "evidence_kind": "static selected-module graph",
        "found": found,
        "required_final_value": False,
        "status": "unmet" if found else "static-absence-only",
        "warning": (
            "Static absence does not prove an optimized artifact omitted equivalent scaffolding; "
            "the final gate still requires runtime/artifact evidence."
        ),
    }


def upstream_stress_capability(root: Path, manifest: Mapping[str, Any]) -> dict[str, object]:
    contracts = required_mapping(manifest["contracts"], "contracts")
    inventory_path = root / required_string(contracts.get("upstream_inventory"), "contracts.upstream_inventory")
    shadow_path = root / required_string(contracts.get("native_shadow_stress"), "contracts.native_shadow_stress")
    inventory = read_json(inventory_path)
    shadow = read_json(shadow_path)
    test_record = next(
        (
            item
            for item in inventory.get("tests", [])
            if isinstance(item, Mapping) and item.get("path") == "test/test-stress.c"
        ),
        None,
    )
    if not isinstance(test_record, Mapping):
        raise RatchetError("upstream test inventory does not record test/test-stress.c")
    status = test_record.get("status")
    patch = shadow.get("patch")
    adapted = isinstance(patch, Mapping) and isinstance(patch.get("path"), str)
    unmodified = status == "unmodified-production-general" and not adapted
    current_workers = 0
    current_large_mode = False
    if unmodified:
        execution = shadow.get("execution")
        if isinstance(execution, Mapping):
            workers = execution.get("source_worker_count")
            current_workers = workers if type(workers) is int else 0
            current_large_mode = "ALLOW_LARGE" not in {
                item.get("macro")
                for item in shadow.get("excluded_upstream_modes", [])
                if isinstance(item, Mapping)
            }
    return {
        "current_large_mode": current_large_mode,
        "current_max_workers": current_workers,
        "evidence_scope": "shadow_subset",
        "inventory_status": status,
        "native_shadow_patch": patch.get("path") if isinstance(patch, Mapping) else None,
        "required_final_large_mode": True,
        "required_final_max_workers": 8,
        "status": "verified" if unmodified else "unmet",
        "warning": (
            "The checked-in native-shadow workload is patched and therefore cannot count as "
            "unmodified upstream stress capability."
        ),
    }


def load_runtime_evidence(path: Path | None, selected: Mapping[str, object]) -> dict[str, object]:
    if path is None:
        return {
            "present": False,
            "status": "absent",
            "warning": "No runtime/artifact evidence was supplied; static source inspection cannot close this gate.",
        }
    evidence = read_json(path)
    if evidence.get("format") != 1 or evidence.get("schema") != RUNTIME_EVIDENCE_SCHEMA:
        raise RatchetError("runtime/artifact evidence has an unsupported schema")
    scope = evidence.get("evidence_scope")
    if scope not in {"production_general", "promotion_qualified"}:
        raise RatchetError("runtime/artifact evidence scope cannot close the architecture gate")
    selection = evidence.get("selected_production")
    if not isinstance(selection, Mapping) or selection.get("feature") != selected.get("feature"):
        raise RatchetError("runtime/artifact evidence does not describe the selected native feature")
    if selection.get("source_sha256") != selected.get("sources"):
        raise RatchetError("runtime/artifact evidence does not match the selected source metadata")
    artifact = evidence.get("artifact")
    if not isinstance(artifact, Mapping) or not isinstance(artifact.get("path"), str):
        raise RatchetError("runtime/artifact evidence does not identify a selected artifact")
    artifact_digest = artifact.get("sha256")
    if not isinstance(artifact_digest, str) or len(artifact_digest) != 64:
        raise RatchetError("runtime/artifact evidence has no selected artifact SHA-256")
    metrics = evidence.get("metrics")
    if not isinstance(metrics, Mapping):
        raise RatchetError("runtime/artifact evidence does not record metrics")
    return {
        "evidence": evidence,
        "present": True,
        "scope": scope,
        "status": "accepted-for-gate-comparison",
    }


def metric_statuses(
    manifest: Mapping[str, Any], signals: Mapping[str, list[SourceMatch]]
) -> dict[str, dict[str, object]]:
    metrics = required_mapping(manifest["metrics"], "metrics")
    result: dict[str, dict[str, object]] = {}
    for name, matches in signals.items():
        metric = required_mapping(metrics[name], f"metrics.{name}")
        final_required = metric["final_required"]
        result[name] = {
            "dynamic_value": "unmeasured",
            "final_required": final_required,
            "source_indicator_count": len(matches),
            "source_indicators": [match.as_dict() for match in matches],
            "static_status": "source-indicates-unmet" if matches else "source-indicates-absence-only",
            "warning": (
                "The source indicator count is not an operation count. It cannot establish the final "
                "value without runtime/artifact evidence."
            ),
        }
    return result


def ratchet_regressions(manifest: Mapping[str, Any], signals: Mapping[str, list[SourceMatch]]) -> list[str]:
    baseline = required_mapping(manifest["ratchet_baseline"], "ratchet_baseline")
    ceilings = required_mapping(baseline["static_signal_ceiling"], "ratchet_baseline.static_signal_ceiling")
    regressions = [
        f"{name}: {len(matches)} source indicators exceed ratchet ceiling {ceilings[name]}"
        for name, matches in signals.items()
        if len(matches) > ceilings[name]
    ]
    return sorted(regressions)


def gate_unmet(report: Mapping[str, Any]) -> list[str]:
    unmet: list[str] = []
    if report["selected_production"]["status"] != "static-selection-confirmed":
        unmet.append("selected production feature/module graph")
    if report["forbidden_scaffolding_compiled"]["compiled_from_selected_source"]:
        unmet.append("forbidden production scaffolding is still selected")
    caller_dispatch = report["caller_identity_first_free_dispatch"]
    if caller_dispatch["status"] == "forbidden":
        unmet.append("caller-identity-first native_free dispatch")
    elif caller_dispatch["status"] == "phase_a_bridge":
        unmet.append("temporary Phase-A caller-identity native_free bridge")
    for name, metric in report["metrics"].items():
        if metric["source_indicator_count"]:
            unmet.append(f"{name} has selected-source indicators")
    stress = report["unmodified_upstream_stress"]
    if stress["status"] != "verified":
        unmet.append("unmodified upstream stress capability")
    runtime = report["runtime_artifact_evidence"]
    if not runtime["present"]:
        unmet.append("production-general runtime/artifact evidence")
    else:
        evidence = runtime["evidence"]
        metrics = evidence["metrics"]
        for name, metric in report["metrics"].items():
            if metrics.get(name) != metric["final_required"]:
                unmet.append(f"runtime evidence {name}")
        if metrics.get("forbidden_scaffolding_compiled") is not False:
            unmet.append("runtime evidence forbidden_scaffolding_compiled")
        if metrics.get("unmodified_upstream_stress_max_workers", 0) < stress["required_final_max_workers"]:
            unmet.append("runtime evidence unmodified_upstream_stress_max_workers")
        if metrics.get("unmodified_upstream_stress_large_mode") is not True:
            unmet.append("runtime evidence unmodified_upstream_stress_large_mode")
    return sorted(set(unmet))


def evaluate(root: Path, manifest_path: Path, runtime_evidence_path: Path | None) -> dict[str, object]:
    manifest = read_json(manifest_path)
    validate_manifest(manifest)
    selected = selected_source_metadata(root, manifest)
    signals = collect_static_signals(root, manifest)
    metrics = metric_statuses(manifest, signals)
    caller_dispatch = caller_identity_first_free_dispatch(root, manifest)
    runtime = load_runtime_evidence(runtime_evidence_path, selected)
    report: dict[str, object] = {
        "format": 1,
        "schema": "crabc-mimalloc-architecture-ratchet-report",
        "scope": required_mapping(manifest["scope"], "scope"),
        "selected_production": selected,
        "metrics": metrics,
        "caller_identity_first_free_dispatch": caller_dispatch,
        "forbidden_scaffolding_compiled": collect_forbidden_scaffolding(root, manifest),
        "unmodified_upstream_stress": upstream_stress_capability(root, manifest),
        "runtime_artifact_evidence": runtime,
        "ratchet": {"regressions": ratchet_regressions(manifest, signals)},
        "structural_violations": (
            ["caller-identity-first native_free dispatch"]
            if caller_dispatch["structural_violation"]
            else []
        ),
    }
    unmet = gate_unmet(report)
    report["summary"] = {
        "final_architecture_passed": not unmet,
        "gate_status": "passed" if not unmet else "unmet",
        "static_analysis_only": not runtime["present"],
        "unmet": unmet,
    }
    return report


def write_json(path: Path, value: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST, help="architecture gate manifest")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT, help="generated report path")
    parser.add_argument("--runtime-evidence", type=Path, help="independent runtime/artifact evidence JSON")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="validate the ratchet and write its current report")
    mode.add_argument("--gate", action="store_true", help="exit nonzero unless the final architecture gate is closed")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        root = arguments.root.resolve()
        manifest = arguments.manifest if arguments.manifest.is_absolute() else root / arguments.manifest
        report_path = arguments.report if arguments.report.is_absolute() else root / arguments.report
        runtime_evidence = arguments.runtime_evidence
        if runtime_evidence is not None and not runtime_evidence.is_absolute():
            runtime_evidence = root / runtime_evidence
        report = evaluate(root, manifest, runtime_evidence)
        write_json(report_path, report)
        print(report_path)
        if report["structural_violations"]:
            raise RatchetError("architecture structural prohibition: " + "; ".join(report["structural_violations"]))
        if report["ratchet"]["regressions"]:
            raise RatchetError("architecture ratchet regressed: " + "; ".join(report["ratchet"]["regressions"]))
        if arguments.gate and not report["summary"]["final_architecture_passed"]:
            raise RatchetError("architecture gate unmet: " + "; ".join(report["summary"]["unmet"]))
        return 0
    except RatchetError as error:
        print(f"allocator architecture ratchet: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
