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


@dataclass(frozen=True)
class RustFunction:
    """One syntactically selected Rust function in the bounded source graph."""

    node: str
    path: str
    name: str
    line: int
    public: bool
    body_line: int
    body: str

    def identity(self) -> dict[str, object]:
        return {
            "function": self.name,
            "line": self.line,
            "path": self.path,
            "public": self.public,
        }


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


def strip_rust_comments(source: str, *, mask_literals: bool = True) -> str:
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
            result.append(
                character if not mask_literals else ("\n" if character == "\n" else " ")
            )
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
        # Rust lifetimes use an apostrophe (`'main`), so mask only the bounded
        # one-codepoint/escaped shape of a character literal. This matters to
        # the brace walker even though the declaration patterns do not match
        # character contents.
        elif character == "'" and re.match(r"'(?:\\.|[^\\'\n])'", source[index:]):
            literal = re.match(r"'(?:\\.|[^\\'\n])'", source[index:])
            assert literal is not None
            result.extend(
                source[index : index + literal.end()]
                if not mask_literals
                else (" " for _ in range(literal.end()))
            )
            index += literal.end()
        elif character == '"':
            in_string = character
            result.append(character if not mask_literals else " ")
            index += 1
        else:
            result.append(character)
            index += 1
    return "".join(result)


def matching_rust_delimiter(source: str, opening: int, left: str, right: str) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise RatchetError(f"selected Rust source has an unclosed {left}{right} delimiter")


def mask_source_range(source: str, start: int, end: int) -> str:
    return source[:start] + "".join(
        "\n" if character == "\n" else " " for character in source[start:end]
    ) + source[end:]


def rust_cfg_attribute_spans(source: str) -> list[tuple[int, int, str]]:
    """Find balanced Rust attributes containing a `cfg(...)` predicate."""

    result: list[tuple[int, int, str]] = []
    cursor = 0
    while True:
        start = source.find("#[", cursor)
        if start < 0:
            return result
        end = matching_rust_delimiter(source, start + 1, "[", "]") + 1
        attribute = source[start:end]
        if re.search(r"\bcfg\s*\(", attribute):
            result.append((start, end, attribute))
        cursor = end


def excluded_cfg_item_end(source: str, attribute_end: int) -> int:
    """Return the end of the item or statement selected by one cfg attribute.

    This is deliberately a narrow lexical boundary, not a Rust parser.  It
    handles the production shapes used here: cfg-gated modules, functions,
    impls, declarations, fields, and block/semicolon statements.  Masking the
    whole outer `#[cfg(test)] mod tests` is what keeps nested harness helpers
    out of the selected production graph.
    """

    cursor = attribute_end
    while True:
        whitespace = re.match(r"\s*", source[cursor:])
        assert whitespace is not None
        cursor += whitespace.end()
        if not source.startswith("#[", cursor):
            break
        cursor = matching_rust_delimiter(source, cursor + 1, "[", "]") + 1

    block_item = re.match(
        r"(?:pub(?:\([^)]*\))?\s+)?"
        r"(?:(?:unsafe|async|const|extern)\s+)*"
        r"(?:fn|mod|impl|trait|struct|enum|union)\b",
        source[cursor:],
    )
    if block_item is not None or source.startswith("{", cursor):
        opening = source.find("{", cursor)
        semicolon = source.find(";", cursor)
        if semicolon >= 0 and (opening < 0 or semicolon < opening):
            return semicolon + 1
        if opening < 0:
            raise RatchetError("cfg-gated Rust block item has no body")
        return matching_rust_delimiter(source, opening, "{", "}") + 1

    field = re.match(r"(?:pub(?:\([^)]*\))?\s+)?[A-Za-z_][A-Za-z0-9_]*\s*:", source[cursor:])
    if field is not None:
        comma = source.find(",", cursor)
        return len(source) if comma < 0 else comma + 1

    semicolon = source.find(";", cursor)
    opening = source.find("{", cursor)
    candidates = [position for position in (semicolon, opening) if position >= 0]
    if not candidates:
        return len(source)
    first = min(candidates)
    if first == opening:
        return matching_rust_delimiter(source, opening, "{", "}") + 1
    return first + 1


def production_rust_source(source: str, excluded_cfg_patterns: list[str]) -> str:
    """Mask comments, strings, and configured test-only/disabled cfg items."""

    code = strip_rust_comments(source)
    cfg_code = strip_rust_comments(source, mask_literals=False)
    excluded_ranges: list[tuple[int, int]] = []
    for start, end, attribute in rust_cfg_attribute_spans(cfg_code):
        if any(re.search(pattern, attribute) for pattern in excluded_cfg_patterns):
            excluded_ranges.append((start, excluded_cfg_item_end(code, end)))
    for start, end in sorted(excluded_ranges, reverse=True):
        code = mask_source_range(code, start, end)
    return code


RUST_FUNCTION_HEADER = re.compile(
    r"\b(?P<header>"
    r"(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:(?:unsafe|async|const|extern)\s+)*"
    r"fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b[^;{}]*\{"
    r")",
    re.MULTILINE,
)


def selected_rust_functions(
    root: Path, relative_path: str, excluded_cfg_patterns: list[str]
) -> list[RustFunction]:
    path = root / relative_path
    if not path.is_file():
        raise RatchetError(f"selected production source is absent: {relative_path}")
    code = production_rust_source(path.read_text(encoding="utf-8"), excluded_cfg_patterns)
    functions: list[RustFunction] = []
    cursor = 0
    while True:
        match = RUST_FUNCTION_HEADER.search(code, cursor)
        if match is None:
            return functions
        opening = code.find("{", match.start("header"), match.end("header"))
        closing = matching_rust_delimiter(code, opening, "{", "}")
        name = match.group("name")
        line = code.count("\n", 0, match.start("header")) + 1
        functions.append(
            RustFunction(
                node=f"{relative_path}:{line}:{name}",
                path=relative_path,
                name=name,
                line=line,
                public=bool(re.search(r"\bpub(?:\([^)]*\))?\s+", match.group("header"))),
                body_line=code.count("\n", 0, opening + 1) + 1,
                body=code[opening + 1 : closing],
            )
        )
        cursor = closing + 1


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


def validate_entry_points(value: object, name: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or not value:
        raise RatchetError(f"architecture manifest {name} must be a non-empty array")
    entries: list[Mapping[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for index, raw_entry in enumerate(value):
        entry = required_mapping(raw_entry, f"{name}[{index}]")
        path = required_string(entry.get("path"), f"{name}[{index}].path")
        function = required_string(entry.get("function"), f"{name}[{index}].function")
        if type(entry.get("public")) is not bool:
            raise RatchetError(f"architecture manifest {name}[{index}].public must be boolean")
        identity = (path, function)
        if identity in identities:
            raise RatchetError(f"architecture manifest {name} repeats {path}::{function}")
        identities.add(identity)
        entries.append(entry)
    return entries


def phase_bc_policy(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    return required_mapping(manifest.get("phase_bc_call_graph"), "phase_bc_call_graph")


def validate_phase_bc_manifest(
    manifest: Mapping[str, Any], metrics: Mapping[str, Any], selected_sources: set[str]
) -> None:
    phase_bc = phase_bc_policy(manifest)
    required_string(phase_bc.get("meaning"), "phase_bc_call_graph.meaning")
    sources = phase_bc.get("sources")
    if not isinstance(sources, list) or not sources or not all(
        isinstance(path, str) and path for path in sources
    ):
        raise RatchetError("architecture manifest phase_bc_call_graph.sources must be string paths")
    missing_selected_sources = sorted(set(sources) - selected_sources)
    if missing_selected_sources:
        raise RatchetError(
            "architecture manifest Phase-B/C sources are absent from selected source hashing: "
            + ", ".join(missing_selected_sources)
        )
    cfg_patterns = phase_bc.get("test_only_cfg_patterns")
    if not isinstance(cfg_patterns, list) or not cfg_patterns or not all(
        isinstance(pattern, str) and pattern for pattern in cfg_patterns
    ):
        raise RatchetError(
            "architecture manifest phase_bc_call_graph.test_only_cfg_patterns must be regex strings"
        )
    for pattern in cfg_patterns:
        try:
            re.compile(pattern)
        except re.error as error:
            raise RatchetError(f"invalid Phase-B/C cfg regex {pattern!r}: {error}") from error
    default_entries = validate_entry_points(
        phase_bc.get("entry_points"), "phase_bc_call_graph.entry_points"
    )
    source_set = set(sources)
    if any(entry["path"] not in source_set for entry in default_entries):
        raise RatchetError("architecture manifest Phase-B/C entry point is outside its source graph")

    ratchets = required_mapping(phase_bc.get("ratchets"), "phase_bc_call_graph.ratchets")
    if not ratchets:
        raise RatchetError("architecture manifest phase_bc_call_graph.ratchets is empty")
    maximum_names: set[str] = set()
    minimum_names: set[str] = set()
    for name, raw_ratchet in ratchets.items():
        if not isinstance(name, str) or not name:
            raise RatchetError("architecture manifest Phase-B/C ratchet name is invalid")
        ratchet = required_mapping(raw_ratchet, f"phase_bc_call_graph.ratchets.{name}")
        patterns = required_mapping(
            ratchet.get("patterns"), f"phase_bc_call_graph.ratchets.{name}.patterns"
        )
        if not patterns:
            raise RatchetError(f"architecture manifest Phase-B/C ratchet {name} has no patterns")
        for pattern_name, pattern in patterns.items():
            if not isinstance(pattern_name, str) or not pattern_name:
                raise RatchetError(f"architecture manifest Phase-B/C ratchet {name} has an invalid pattern name")
            regex = required_string(
                pattern, f"phase_bc_call_graph.ratchets.{name}.patterns.{pattern_name}"
            )
            try:
                re.compile(regex)
            except re.error as error:
                raise RatchetError(
                    f"invalid Phase-B/C ratchet regex {name}.{pattern_name}: {error}"
                ) from error
        entries = validate_entry_points(
            ratchet.get("entry_points", default_entries),
            f"phase_bc_call_graph.ratchets.{name}.entry_points",
        )
        if any(entry["path"] not in source_set for entry in entries):
            raise RatchetError(f"architecture manifest Phase-B/C ratchet {name} has an external entry")
        covered_metrics = ratchet.get("covered_metrics")
        if not isinstance(covered_metrics, list) or not all(
            isinstance(metric, str) and metric in metrics for metric in covered_metrics
        ):
            raise RatchetError(f"architecture manifest Phase-B/C ratchet {name} covers an unknown metric")
        direction = ratchet.get("direction")
        if direction == "maximum":
            maximum_names.add(name)
            if ratchet.get("final_required") != 0:
                raise RatchetError(
                    f"architecture manifest Phase-B/C maximum {name} must retain final_required 0"
                )
        elif direction == "minimum_per_pattern":
            minimum_names.add(name)
            required_string(
                ratchet.get("final_required"),
                f"phase_bc_call_graph.ratchets.{name}.final_required",
            )
        else:
            raise RatchetError(f"architecture manifest Phase-B/C ratchet {name} has invalid direction")

    runtime_required = required_mapping(
        phase_bc.get("runtime_evidence_required"),
        "phase_bc_call_graph.runtime_evidence_required",
    )
    phase_b = required_mapping(
        runtime_required.get("phase_b"),
        "phase_bc_call_graph.runtime_evidence_required.phase_b",
    )
    if phase_b.get("persistent_thread_local_owner") is not True:
        raise RatchetError("architecture manifest Phase-B evidence must require a persistent TLS owner")
    local = required_mapping(
        phase_b.get("local_steady_state"),
        "phase_bc_call_graph.runtime_evidence_required.phase_b.local_steady_state",
    )
    expected_local = {
        "client_ledger_scans": 0,
        "global_pagemap_mutation_leases": 0,
        "owner_registry_scans": 0,
        "per_call_engine_park_resume": False,
        "process_scheduler_ops": 0,
    }
    if dict(local) != expected_local:
        raise RatchetError("architecture manifest Phase-B local steady-state requirements changed")
    phase_c = required_mapping(
        runtime_required.get("phase_c"),
        "phase_bc_call_graph.runtime_evidence_required.phase_c",
    )
    expected_phase_c = {
        "canonical_block_recovery": True,
        "native_free_pointer_first": True,
        "owner_or_thread_count_dependent_lookup": False,
        "page_local_remote_publication": True,
        "pointer_to_page_lookup": True,
    }
    if dict(phase_c) != expected_phase_c:
        raise RatchetError("architecture manifest Phase-C pointer-dispatch requirements changed")

    baseline = required_mapping(manifest.get("ratchet_baseline"), "ratchet_baseline")
    ceilings = required_mapping(
        baseline.get("phase_bc_selected_production_reachable_ceiling"),
        "ratchet_baseline.phase_bc_selected_production_reachable_ceiling",
    )
    if set(ceilings) != maximum_names or not all(
        type(value) is int and value >= 0 for value in ceilings.values()
    ):
        raise RatchetError("architecture manifest Phase-B/C reachable ceilings are incomplete")
    floors = required_mapping(
        baseline.get("phase_bc_selected_production_reachable_floor_per_pattern"),
        "ratchet_baseline.phase_bc_selected_production_reachable_floor_per_pattern",
    )
    if set(floors) != minimum_names:
        raise RatchetError("architecture manifest Phase-B/C reachable floors are incomplete")
    for name in minimum_names:
        ratchet = required_mapping(ratchets[name], f"phase_bc_call_graph.ratchets.{name}")
        floor = required_mapping(
            floors[name],
            f"ratchet_baseline.phase_bc_selected_production_reachable_floor_per_pattern.{name}",
        )
        patterns = required_mapping(
            ratchet["patterns"], f"phase_bc_call_graph.ratchets.{name}.patterns"
        )
        if set(floor) != set(patterns) or not all(
            type(value) is int and value >= 0 for value in floor.values()
        ):
            raise RatchetError(f"architecture manifest Phase-B/C reachable floor {name} is incomplete")


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
    validate_phase_bc_manifest(manifest, metrics, set(sources))


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


RUST_CALL_SITE = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:::\s*<[^(){};]*>)?\s*\(",
    re.MULTILINE,
)


def resolve_phase_bc_entry_points(
    functions: list[RustFunction], raw_entries: object, name: str
) -> list[RustFunction]:
    entries = validate_entry_points(raw_entries, name)
    resolved: list[RustFunction] = []
    for entry in entries:
        candidates = [
            function
            for function in functions
            if function.path == entry["path"]
            and function.name == entry["function"]
            and function.public is entry["public"]
        ]
        if len(candidates) != 1:
            raise RatchetError(
                f"selected Phase-B/C entry {entry['path']}::{entry['function']} resolves to "
                f"{len(candidates)} functions"
            )
        function = candidates[0]
        resolved.append(function)
    return resolved


def phase_bc_call_edges(functions: list[RustFunction]) -> dict[str, set[str]]:
    """Build a deliberately conservative, name-resolved syntactic call graph.

    A method call may resolve to more than one same-named selected function;
    all such definitions are therefore may-reachable.  That over-approximation
    can retain an architecture warning, but it cannot incorrectly hide a
    forbidden call site.  Definitions outside the selected source set remain
    outside this bounded source witness and require the independent artifact
    evidence demanded by the manifest.
    """

    functions_by_name: dict[str, set[str]] = {}
    for function in functions:
        functions_by_name.setdefault(function.name, set()).add(function.node)
    return {
        function.node: {
            target
            for match in RUST_CALL_SITE.finditer(function.body)
            for target in functions_by_name.get(match.group("name"), set())
        }
        for function in functions
    }


def phase_bc_reachable_functions(
    entries: list[RustFunction],
    functions_by_node: Mapping[str, RustFunction],
    edges: Mapping[str, set[str]],
) -> tuple[set[str], dict[str, str | None]]:
    queue = [entry.node for entry in entries]
    reachable = set(queue)
    predecessor: dict[str, str | None] = {entry.node: None for entry in entries}
    while queue:
        current = queue.pop(0)
        for target in sorted(edges.get(current, set())):
            if target not in functions_by_node or target in reachable:
                continue
            reachable.add(target)
            predecessor[target] = current
            queue.append(target)
    return reachable, predecessor


def phase_bc_call_chain(
    node: str,
    predecessor: Mapping[str, str | None],
    functions_by_node: Mapping[str, RustFunction],
) -> list[dict[str, object]]:
    nodes: list[str] = []
    current: str | None = node
    while current is not None:
        nodes.append(current)
        current = predecessor[current]
    return [functions_by_node[item].identity() for item in reversed(nodes)]


def phase_bc_ratchet_matches(
    ratchet_name: str,
    ratchet: Mapping[str, Any],
    default_entries: object,
    functions: list[RustFunction],
    functions_by_node: Mapping[str, RustFunction],
    edges: Mapping[str, set[str]],
) -> tuple[list[dict[str, object]], dict[str, int], list[RustFunction]]:
    entries = resolve_phase_bc_entry_points(
        functions,
        ratchet.get("entry_points", default_entries),
        f"phase_bc_call_graph.ratchets.{ratchet_name}.entry_points",
    )
    reachable, predecessor = phase_bc_reachable_functions(entries, functions_by_node, edges)
    matches: list[dict[str, object]] = []
    pattern_counts: dict[str, int] = {}
    patterns = required_mapping(
        ratchet["patterns"], f"phase_bc_call_graph.ratchets.{ratchet_name}.patterns"
    )
    for pattern_name, raw_pattern in patterns.items():
        pattern = required_string(
            raw_pattern, f"phase_bc_call_graph.ratchets.{ratchet_name}.patterns.{pattern_name}"
        )
        pattern_count = 0
        for node in sorted(reachable):
            function = functions_by_node[node]
            for match in re.finditer(pattern, function.body, flags=re.MULTILINE):
                pattern_count += 1
                matches.append(
                    {
                        "call_chain": phase_bc_call_chain(node, predecessor, functions_by_node),
                        "function": function.name,
                        "line": function.body_line + function.body.count("\n", 0, match.start()),
                        "path": function.path,
                        "pattern": pattern,
                        "pattern_name": pattern_name,
                    }
                )
        pattern_counts[pattern_name] = pattern_count
    matches.sort(key=lambda item: (item["path"], item["line"], item["pattern_name"]))
    reachable_functions = sorted(
        (functions_by_node[node] for node in reachable),
        key=lambda function: (function.path, function.line, function.name),
    )
    return matches, pattern_counts, reachable_functions


def phase_bc_selected_production_reachability(
    root: Path, manifest: Mapping[str, Any]
) -> dict[str, object]:
    """Evaluate Phase-B/C source requirements without claiming runtime proof."""

    policy = phase_bc_policy(manifest)
    cfg_patterns = [
        required_string(pattern, "phase_bc_call_graph.test_only_cfg_patterns[]")
        for pattern in policy["test_only_cfg_patterns"]
    ]
    functions = [
        function
        for path in policy["sources"]
        for function in selected_rust_functions(root, path, cfg_patterns)
    ]
    functions_by_node = {function.node: function for function in functions}
    edges = phase_bc_call_edges(functions)
    default_entries = policy["entry_points"]
    entries = resolve_phase_bc_entry_points(
        functions, default_entries, "phase_bc_call_graph.entry_points"
    )
    overall_reachable, _ = phase_bc_reachable_functions(entries, functions_by_node, edges)
    baseline = required_mapping(manifest["ratchet_baseline"], "ratchet_baseline")
    ceilings = required_mapping(
        baseline["phase_bc_selected_production_reachable_ceiling"],
        "ratchet_baseline.phase_bc_selected_production_reachable_ceiling",
    )
    floors = required_mapping(
        baseline["phase_bc_selected_production_reachable_floor_per_pattern"],
        "ratchet_baseline.phase_bc_selected_production_reachable_floor_per_pattern",
    )
    reports: dict[str, dict[str, object]] = {}
    regressions: list[str] = []
    for ratchet_name, raw_ratchet in required_mapping(
        policy["ratchets"], "phase_bc_call_graph.ratchets"
    ).items():
        ratchet = required_mapping(raw_ratchet, f"phase_bc_call_graph.ratchets.{ratchet_name}")
        matches, pattern_counts, ratchet_reachable = phase_bc_ratchet_matches(
            ratchet_name,
            ratchet,
            default_entries,
            functions,
            functions_by_node,
            edges,
        )
        count = len(matches)
        direction = ratchet["direction"]
        common: dict[str, object] = {
            "covered_metrics": list(ratchet["covered_metrics"]),
            "direction": direction,
            "entry_points": [function.identity() for function in resolve_phase_bc_entry_points(
                functions,
                ratchet.get("entry_points", default_entries),
                f"phase_bc_call_graph.ratchets.{ratchet_name}.entry_points",
            )],
            "final_acceptance": False,
            "final_required": ratchet["final_required"],
            "matches": matches,
            "pattern_counts": pattern_counts,
            "reachable_function_count": len(ratchet_reachable),
            "reachable_indicator_count": count,
        }
        if direction == "maximum":
            ceiling = ceilings[ratchet_name]
            within_ceiling = count <= ceiling
            static_requirement_met = count <= ratchet["final_required"]
            common.update(
                {
                    "ratchet_ceiling": ceiling,
                    "static_final_requirement_met": static_requirement_met,
                    "status": (
                        "static-absence-only"
                        if static_requirement_met
                        else "selected-production-reachable"
                    ),
                    "within_ratchet_ceiling": within_ceiling,
                }
            )
            if not within_ceiling:
                regressions.append(
                    f"phase_bc {ratchet_name}: {count} selected-production-reachable "
                    f"indicators exceed ratchet ceiling {ceiling}"
                )
        else:
            floor = required_mapping(
                floors[ratchet_name],
                f"ratchet_baseline.phase_bc_selected_production_reachable_floor_per_pattern.{ratchet_name}",
            )
            below_floor = {
                pattern_name: {"actual": pattern_counts[pattern_name], "floor": required}
                for pattern_name, required in floor.items()
                if pattern_counts[pattern_name] < required
            }
            common.update(
                {
                    "below_ratchet_floor": below_floor,
                    "ratchet_floor_per_pattern": dict(floor),
                    "static_projection_present": not below_floor,
                    "status": "missing-static-projection" if below_floor else "static-projection-only",
                    "within_ratchet_floor": not below_floor,
                }
            )
            for pattern_name, values in sorted(below_floor.items()):
                regressions.append(
                    f"phase_bc {ratchet_name}.{pattern_name}: {values['actual']} "
                    f"selected-production-reachable indicators fall below ratchet floor {values['floor']}"
                )
        reports[ratchet_name] = common
    return {
        "entry_points": [function.identity() for function in entries],
        "evidence_kind": "syntactic selected-source may-reachability",
        "final_acceptance": False,
        "meaning": policy["meaning"],
        "ratchets": reports,
        "reachable_functions": [
            functions_by_node[node].identity()
            for node in sorted(
                overall_reachable,
                key=lambda node: (
                    functions_by_node[node].path,
                    functions_by_node[node].line,
                    functions_by_node[node].name,
                ),
            )
        ],
        "regressions": sorted(regressions),
        "runtime_evidence_required": policy["runtime_evidence_required"],
        "warning": (
            "Syntactic may-reachability can expose selected call sites or a missing source "
            "projection. It cannot establish dynamic frequency, emitted-artifact behavior, "
            "or production-general runtime completion."
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


def required_evidence_shape(
    actual: object, required: object, path: str
) -> None:
    """Require every checked-in Phase-B/C field without accepting omissions."""

    if isinstance(required, Mapping):
        if not isinstance(actual, Mapping):
            raise RatchetError(f"runtime/artifact evidence is missing Phase-B/C object: {path}")
        for name, required_value in required.items():
            if name not in actual:
                raise RatchetError(
                    f"runtime/artifact evidence is missing Phase-B/C field: {path}.{name}"
                )
            required_evidence_shape(actual[name], required_value, f"{path}.{name}")
        return
    if type(actual) is not type(required):
        raise RatchetError(f"runtime/artifact evidence Phase-B/C field has wrong type: {path}")


def phase_bc_evidence_mismatches(
    actual: object, required: object, path: str = "phase_bc"
) -> list[str]:
    if isinstance(required, Mapping):
        if not isinstance(actual, Mapping):
            return [path]
        return [
            mismatch
            for name, required_value in required.items()
            for mismatch in phase_bc_evidence_mismatches(
                actual.get(name), required_value, f"{path}.{name}"
            )
        ]
    return [] if actual == required else [path]


def load_runtime_evidence(
    path: Path | None,
    selected: Mapping[str, object],
    manifest: Mapping[str, Any] | None = None,
) -> dict[str, object]:
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
    if manifest is None:
        raise RatchetError("runtime/artifact evidence validation requires the architecture manifest")
    required_phase_bc = required_mapping(
        phase_bc_policy(manifest).get("runtime_evidence_required"),
        "phase_bc_call_graph.runtime_evidence_required",
    )
    phase_bc = evidence.get("phase_bc")
    required_evidence_shape(phase_bc, required_phase_bc, "phase_bc")
    return {
        "evidence": evidence,
        "present": True,
        "required_phase_bc": required_phase_bc,
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
    phase_bc = report["phase_bc_selected_production_reachability"]
    for name, ratchet in phase_bc["ratchets"].items():
        if ratchet["direction"] == "maximum" and not ratchet["static_final_requirement_met"]:
            unmet.append(f"Phase B/C {name} has selected-production-reachable indicators")
        elif ratchet["direction"] == "minimum_per_pattern" and not ratchet["static_projection_present"]:
            unmet.append(f"Phase B/C {name} lacks its selected-production source projection")
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
        required_phase_bc = runtime["required_phase_bc"]
        for mismatch in phase_bc_evidence_mismatches(
            evidence.get("phase_bc"), required_phase_bc
        ):
            unmet.append(f"runtime evidence {mismatch}")
    return sorted(set(unmet))


def evaluate(root: Path, manifest_path: Path, runtime_evidence_path: Path | None) -> dict[str, object]:
    manifest = read_json(manifest_path)
    validate_manifest(manifest)
    selected = selected_source_metadata(root, manifest)
    signals = collect_static_signals(root, manifest)
    metrics = metric_statuses(manifest, signals)
    caller_dispatch = caller_identity_first_free_dispatch(root, manifest)
    phase_bc = phase_bc_selected_production_reachability(root, manifest)
    runtime = load_runtime_evidence(runtime_evidence_path, selected, manifest)
    report: dict[str, object] = {
        "format": 1,
        "schema": "crabc-mimalloc-architecture-ratchet-report",
        "scope": required_mapping(manifest["scope"], "scope"),
        "selected_production": selected,
        "metrics": metrics,
        "caller_identity_first_free_dispatch": caller_dispatch,
        "phase_bc_selected_production_reachability": phase_bc,
        "forbidden_scaffolding_compiled": collect_forbidden_scaffolding(root, manifest),
        "unmodified_upstream_stress": upstream_stress_capability(root, manifest),
        "runtime_artifact_evidence": runtime,
        "ratchet": {
            "regressions": sorted(
                [*ratchet_regressions(manifest, signals), *phase_bc["regressions"]]
            )
        },
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
