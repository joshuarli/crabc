#!/usr/bin/env python3
"""Evaluate the native-mimalloc architecture ratchet without promotion claims.

The current native allocator is a bounded ``native-mimalloc-shadow`` route.
This evaluator records that fact from the selected source/module graph and its
checked-in workload contracts.  Static inspection is deliberately useful only
as a negative architecture witness: it can show that known scaffolding is
still selected, but it cannot prove that a hot path has no operation.  A final
gate therefore also requires an independently generated runtime/artifact
evidence record with the manifest's exact promotion-qualified scope.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "compat/allocator/architecture-gate-v3.5.0.json"
DEFAULT_REPORT = ROOT / "target/architecture-ratchet/latest.json"
RUNTIME_EVIDENCE_SCHEMA = "crabc-mimalloc-architecture-runtime-evidence"
PROMOTION_BENCHMARK_METRICS = (
    "cross_thread_free_throughput_ratio",
    "four_thread_local_throughput_ratio",
    "metadata_plateau_after_warmup",
    "single_thread_throughput_ratio",
)


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


class CfgParser:
    """Evaluate the deliberately closed production cfg environment."""

    TOKEN = re.compile(
        r'\s*(?:(?P<identifier>[A-Za-z_][A-Za-z0-9_-]*)|'
        r'(?P<string>"(?:\\.|[^"\\])*")|(?P<punctuation>[(),=]))'
    )

    def __init__(self, expression: str, environment: Mapping[str, Any]) -> None:
        self.expression = expression
        self.environment = environment
        self.tokens: list[tuple[str, str]] = []
        cursor = 0
        while cursor < len(expression):
            if not expression[cursor:].strip():
                break
            match = self.TOKEN.match(expression, cursor)
            if match is None:
                raise RatchetError(
                    f"unsupported production cfg syntax: {expression[cursor:]!r}"
                )
            kind = next(name for name, value in match.groupdict().items() if value is not None)
            self.tokens.append((kind, match.group(kind)))
            cursor = match.end()
        self.cursor = 0

    def peek(self, value: str) -> bool:
        return self.cursor < len(self.tokens) and self.tokens[self.cursor][1] == value

    def take(self, kind: str | None = None, value: str | None = None) -> str:
        if self.cursor >= len(self.tokens):
            raise RatchetError("production cfg expression ended unexpectedly")
        token_kind, token_value = self.tokens[self.cursor]
        if kind is not None and token_kind != kind:
            raise RatchetError(f"production cfg expected {kind}, found {token_value!r}")
        if value is not None and token_value != value:
            raise RatchetError(f"production cfg expected {value!r}, found {token_value!r}")
        self.cursor += 1
        return token_value

    def parse(self) -> bool:
        result = self.parse_predicate()
        if self.cursor != len(self.tokens):
            raise RatchetError(
                f"production cfg has trailing syntax: {self.tokens[self.cursor][1]!r}"
            )
        return result

    def parse_predicate(self) -> bool:
        name = self.take("identifier")
        if self.peek("("):
            self.take(value="(")
            values: list[bool] = []
            if not self.peek(")"):
                while True:
                    values.append(self.parse_predicate())
                    if not self.peek(","):
                        break
                    self.take(value=",")
                    if self.peek(")"):
                        break
            self.take(value=")")
            if name == "all":
                return all(values)
            if name == "any":
                return any(values)
            if name == "not" and len(values) == 1:
                return not values[0]
            raise RatchetError(f"unsupported production cfg operator: {name}")
        if self.peek("="):
            self.take(value="=")
            raw_value = self.take("string")
            try:
                value = json.loads(raw_value)
            except json.JSONDecodeError as error:
                raise RatchetError(f"invalid production cfg string: {raw_value}") from error
            if name == "feature":
                features = required_mapping(
                    self.environment.get("features"), "phase_bc_call_graph.cfg_environment.features"
                )
                if value not in features or type(features[value]) is not bool:
                    raise RatchetError(f"unknown production cfg feature: {value}")
                return bool(features[value])
            key_values = required_mapping(
                self.environment.get("key_values"),
                "phase_bc_call_graph.cfg_environment.key_values",
            )
            if name not in key_values or not isinstance(key_values[name], str):
                raise RatchetError(f"unknown production cfg key: {name}")
            return key_values[name] == value
        flags = required_mapping(
            self.environment.get("flags"), "phase_bc_call_graph.cfg_environment.flags"
        )
        if name not in flags or type(flags[name]) is not bool:
            raise RatchetError(f"unknown production cfg flag: {name}")
        return bool(flags[name])


def cfg_attribute_expression(attribute: str) -> str:
    match = re.search(r"#\s*\[\s*cfg\s*\(", attribute)
    if match is None:
        raise RatchetError("selected Rust cfg attribute has an unsupported shape")
    opening = attribute.find("(", match.start())
    closing = matching_rust_delimiter(attribute, opening, "(", ")")
    if attribute[closing + 1 :].strip() != "]":
        raise RatchetError("selected Rust cfg attribute has trailing syntax")
    return attribute[opening + 1 : closing]


def production_rust_source(source: str, cfg_environment: Mapping[str, Any]) -> str:
    """Mask comments, strings, and cfg items not selected in production."""

    code = strip_rust_comments(source)
    cfg_code = strip_rust_comments(source, mask_literals=False)
    excluded_ranges: list[tuple[int, int]] = []
    for start, end, attribute in rust_cfg_attribute_spans(cfg_code):
        expression = cfg_attribute_expression(attribute)
        if not CfgParser(expression, cfg_environment).parse():
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
    root: Path, relative_path: str, cfg_environment: Mapping[str, Any]
) -> list[RustFunction]:
    path = root / relative_path
    if not path.is_file():
        raise RatchetError(f"selected production source is absent: {relative_path}")
    code = production_rust_source(path.read_text(encoding="utf-8"), cfg_environment)
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


def source_matches(
    root: Path,
    relative_path: str,
    pattern: str,
    cfg_environment: Mapping[str, Any] | None = None,
) -> list[SourceMatch]:
    path = root / relative_path
    if not path.is_file():
        raise RatchetError(f"selected production source is absent: {relative_path}")
    raw_source = path.read_text(encoding="utf-8")
    source = (
        production_rust_source(raw_source, cfg_environment)
        if cfg_environment is not None
        else strip_rust_comments(raw_source)
    )
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
    cfg_environment = required_mapping(
        phase_bc.get("cfg_environment"), "phase_bc_call_graph.cfg_environment"
    )
    flags = required_mapping(
        cfg_environment.get("flags"), "phase_bc_call_graph.cfg_environment.flags"
    )
    features = required_mapping(
        cfg_environment.get("features"), "phase_bc_call_graph.cfg_environment.features"
    )
    key_values = required_mapping(
        cfg_environment.get("key_values"), "phase_bc_call_graph.cfg_environment.key_values"
    )
    if not flags or not all(isinstance(name, str) and type(value) is bool for name, value in flags.items()):
        raise RatchetError("architecture manifest production cfg flags must be booleans")
    if not features or not all(
        isinstance(name, str) and type(value) is bool for name, value in features.items()
    ):
        raise RatchetError("architecture manifest production cfg features must be booleans")
    if not key_values or not all(
        isinstance(name, str) and isinstance(value, str) and value
        for name, value in key_values.items()
    ):
        raise RatchetError("architecture manifest production cfg key-values must be strings")
    if flags.get("test") is not False:
        raise RatchetError("architecture manifest production cfg must select cfg(not(test))")
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
    required_string(scope.get("final_required"), "scope.final_required")
    runtime_evidence = required_mapping(manifest.get("runtime_evidence"), "runtime_evidence")
    if runtime_evidence.get("format") != 1 or runtime_evidence.get("schema") != RUNTIME_EVIDENCE_SCHEMA:
        raise RatchetError("architecture manifest runtime evidence contract drifted")
    producer = required_mapping(
        runtime_evidence.get("promotion_benchmark_producer"),
        "runtime_evidence.promotion_benchmark_producer",
    )
    if producer.get("schema") is not None or producer.get("status") != "not-registered":
        raise RatchetError("architecture manifest names an unreviewed benchmark producer schema")
    observations = producer.get("required_observations")
    if not isinstance(observations, list) or not observations or not all(
        isinstance(value, str) and value for value in observations
    ):
        raise RatchetError("architecture manifest benchmark producer observations are incomplete")
    if producer.get("required_metrics") != list(PROMOTION_BENCHMARK_METRICS):
        raise RatchetError("architecture manifest benchmark producer metric inventory drifted")
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
    contracts = required_mapping(manifest.get("contracts"), "contracts")
    if set(contracts) != {"canonical_upstream_stress"}:
        raise RatchetError("architecture manifest must select the canonical upstream stress contract")
    required_string(
        contracts.get("canonical_upstream_stress"), "contracts.canonical_upstream_stress"
    )
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
    cfg_environment = required_mapping(
        phase_bc_policy(manifest)["cfg_environment"], "phase_bc_call_graph.cfg_environment"
    )

    def production_matches(path: str, pattern: str) -> list[SourceMatch]:
        return source_matches(root, path, pattern, cfg_environment)

    signals = {
        "local_hot_path_process_scheduler_ops": [
            *production_matches(runtime, r"\bpage_owner_state\s*:\s*AtomicUsize\b"),
            *production_matches(runtime, r"\.page_owner_state\s*\.compare_exchange(?:_weak)?\s*\("),
        ],
        "local_hot_path_global_pagemap_leases": [
            *production_matches(runtime, r"\bProcessPageMapLease\b"),
            *production_matches(page_map, r"\bstruct\s+ProcessPageMapMutationLease\b"),
        ],
        "local_operation_owner_registry_scans": [
            *production_matches(runtime, r"\bfn\s+claim_current_slot(?:_excluding_held_route)?\s*\("),
            *production_matches(runtime, r"\bwhile\s*!current\.is_null\(\)\s*\{"),
        ],
        "local_operation_client_ledger_scans": [
            *production_matches(runtime, r"\bstruct\s+PreparedOwnerExitClients\b"),
            *production_matches(runtime, r"\bfor\s+slot\s+in\s+0\.\.self\.slot_count\(\)\s*\{"),
            *production_matches(runtime, r"\bsession\.clients\.native_client_for_block\s*\("),
        ],
        "remote_free_owner_registry_scans": [
            *production_matches(runtime, r"\bfn\s+claim_exact_client\s*\("),
            *production_matches(runtime, r"\bfn\s+usable_size_exact\s*\("),
            *production_matches(runtime, r"\bwhile\s*!current\.is_null\(\)\s*\{"),
        ],
        "extra_control_bytes_per_live_allocation": [
            *production_matches(runtime, r"\bstruct\s+PreparedOwnerExitClient\b"),
            *production_matches(runtime, r"\benum\s+DetachedOwnerExitClientLedger\b"),
        ],
        "per_call_engine_park_resume": [
            *production_matches(runtime, r"\bfn\s+suspend\s*\("),
            *production_matches(runtime, r"\bfn\s+resume\s*<"),
            *production_matches(runtime, r"\.suspend\(\)"),
            *production_matches(runtime, r"\.resume\("),
        ],
        "exited_owner_admission_survives_thread_exit": [
            *production_matches(runtime, r"\bstruct\s+LaterThreadAdmissionClaim\b"),
            *production_matches(runtime, r"\badmission\s*:\s*LaterThreadAdmissionClaim\b"),
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


PAGE_MAP_LIVE_ALLOCATION_LOOKUP = re.compile(r"\.lookup_live_allocation\s*\(")
SOURCE_ALLOCATION_ASSOCIATION = re.compile(
    r"\b(?P<allocation>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*is_associated_with\s*\(\s*"
    r"(?P<current>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
)
NEGATIVE_SOURCE_ALLOCATION_ASSOCIATION = re.compile(
    r"\bif\s*!\s*\(?\s*(?P<allocation>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"is_associated_with\s*\(\s*(?P<current>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\)?\s*\{"
)
UNAVAILABLE_ALLOCATION_RESULT = re.compile(
    r"\breturn\s+Err\s*\(\s*NativePageAllocationResult\s*::\s*Unavailable\s*\)"
)
RUST_FREE_CALL_SITE = re.compile(
    r"(?<![A-Za-z0-9_.])(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:::\s*<[^(){};]*>)?\s*\(",
    re.MULTILINE,
)


def native_reallocate_pointer_first_dispatch(
    root: Path, manifest: Mapping[str, Any]
) -> dict[str, object]:
    """Reject a selected-source realloc path that refuses a foreign PageMap fact.

    The bounded witness starts at the public `native_reallocate` boundary and
    follows only name-resolved helpers in the selected runtime source.  It
    records the source PageMap lookup before an association decision, then
    rejects the precise legacy branch that classifies a foreign source against
    the caller's current identity and returns `Unavailable`.  This cannot
    prove a complete realloc implementation; it prevents that known nonlocal
    refusal from being reintroduced while the broader architecture remains
    runtime-evidence gated.
    """

    selected = required_mapping(manifest["selected_production"], "selected_production")
    path = required_string(
        selected.get("runtime_source"), "selected_production.runtime_source"
    )
    cfg_environment = required_mapping(
        phase_bc_policy(manifest)["cfg_environment"], "phase_bc_call_graph.cfg_environment"
    )
    functions = selected_rust_functions(root, path, cfg_environment)
    functions_by_node = {function.node: function for function in functions}
    functions_by_name: dict[str, set[str]] = {}
    for function in functions:
        functions_by_name.setdefault(function.name, set()).add(function.node)
    entries = [
        function
        for function in functions
        if function.name == "native_reallocate" and function.public
    ]
    if len(entries) != 1:
        raise RatchetError(
            "selected runtime source resolves native_reallocate to "
            f"{len(entries)} public functions"
        )
    entry = entries[0]
    # `RUST_CALL_SITE` intentionally over-approximates methods for the broad
    # Phase-B/C witness.  That would pull unrelated `free`, `drop`, and
    # `allocate` methods into this narrow reallocation boundary, so resolve
    # only unambiguous free-function calls here.  The null-pointer allocation
    # arm is intentionally outside old-pointer source routing.
    edges: dict[str, set[str]] = {}
    call_offsets: dict[tuple[str, str], list[int]] = {}
    for function in functions:
        targets: set[str] = set()
        for call in RUST_FREE_CALL_SITE.finditer(function.body):
            candidates = functions_by_name.get(call.group("name"), set())
            if len(candidates) != 1:
                continue
            target = next(iter(candidates))
            if (
                function.node == entry.node
                and functions_by_node[target].name == "native_allocate_aligned"
            ):
                continue
            targets.add(target)
            call_offsets.setdefault((function.node, target), []).append(call.start())
        edges[function.node] = targets
    reachable, predecessor = phase_bc_reachable_functions(entries, functions_by_node, edges)

    # Compute the complete reverse closure once instead of recursively asking
    # whether each prefix helper can reach a lookup. Realloc helpers can form
    # ordinary cycles through release, allocation, and generic-free support;
    # this fixed-point walk is linear in the bounded selected function graph
    # and treats a cycle with no PageMap witness as no witness.
    reverse_edges: dict[str, set[str]] = {node: set() for node in functions_by_node}
    for caller, targets in edges.items():
        for target in targets:
            reverse_edges[target].add(caller)
    page_map_lookup_reachable = {
        node
        for node, function in functions_by_node.items()
        if PAGE_MAP_LIVE_ALLOCATION_LOOKUP.search(function.body)
    }
    pending_lookup_callers = list(page_map_lookup_reachable)
    while pending_lookup_callers:
        target = pending_lookup_callers.pop()
        for caller in reverse_edges[target]:
            if caller not in page_map_lookup_reachable:
                page_map_lookup_reachable.add(caller)
                pending_lookup_callers.append(caller)

    def source_lookup_in_prefix(function: RustFunction, offset: int) -> bool:
        prefix = function.body[:offset]
        if PAGE_MAP_LIVE_ALLOCATION_LOOKUP.search(prefix):
            return True
        for call in RUST_FREE_CALL_SITE.finditer(prefix):
            targets = functions_by_name.get(call.group("name"), set())
            # An ambiguous local name is not a source-fact witness. The
            # precomputed closure makes this query bounded even when helpers
            # recursively route through allocation/free support.
            if len(targets) == 1 and next(iter(targets)) in page_map_lookup_reachable:
                return True
        return False

    def source_lookup_precedes(function: RustFunction, offset: int) -> bool:
        if source_lookup_in_prefix(function, offset):
            return True
        child = function.node
        parent = predecessor.get(child)
        while parent is not None:
            offsets = call_offsets.get((parent, child), [])
            if any(
                source_lookup_in_prefix(functions_by_node[parent], call_offset)
                for call_offset in offsets
            ):
                return True
            child = parent
            parent = predecessor.get(child)
        return False

    def source_match(function: RustFunction, offset: int, pattern: str) -> dict[str, object]:
        return {
            "call_chain": phase_bc_call_chain(function.node, predecessor, functions_by_node),
            "function": function.name,
            "line": function.body_line + function.body.count("\n", 0, offset),
            "path": function.path,
            "pattern": pattern,
        }

    page_map_lookups: list[dict[str, object]] = []
    source_routing_decisions: list[dict[str, object]] = []
    caller_current_refusals: list[dict[str, object]] = []
    for node in sorted(reachable):
        function = functions_by_node[node]
        for match in PAGE_MAP_LIVE_ALLOCATION_LOOKUP.finditer(function.body):
            page_map_lookups.append(
                source_match(function, match.start(), PAGE_MAP_LIVE_ALLOCATION_LOOKUP.pattern)
            )
        for match in SOURCE_ALLOCATION_ASSOCIATION.finditer(function.body):
            decision = source_match(function, match.start(), SOURCE_ALLOCATION_ASSOCIATION.pattern)
            decision["page_map_fact_precedes"] = source_lookup_precedes(function, match.start())
            source_routing_decisions.append(decision)
        for match in NEGATIVE_SOURCE_ALLOCATION_ASSOCIATION.finditer(function.body):
            opening = match.end() - 1
            closing = matching_rust_delimiter(function.body, opening, "{", "}")
            branch = function.body[opening + 1 : closing]
            current = match.group("current")
            current_binding = re.compile(
                rf"\blet\s+(?:Some\s*\(\s*)?{re.escape(current)}\s*\)?\s*=\s*"
                r"current_thread_identity\s*\("
            )
            if not current_binding.search(function.body[: match.start()]):
                continue
            if not UNAVAILABLE_ALLOCATION_RESULT.search(branch):
                continue
            refusal = source_match(
                function, match.start(), NEGATIVE_SOURCE_ALLOCATION_ASSOCIATION.pattern
            )
            refusal["page_map_fact_precedes"] = source_lookup_precedes(function, match.start())
            caller_current_refusals.append(refusal)

    page_map_lookups.sort(key=lambda item: (item["path"], item["line"], item["function"]))
    source_routing_decisions.sort(
        key=lambda item: (item["path"], item["line"], item["function"])
    )
    caller_current_refusals.sort(
        key=lambda item: (item["path"], item["line"], item["function"])
    )
    page_map_first = bool(page_map_lookups) and all(
        bool(item["page_map_fact_precedes"]) for item in source_routing_decisions
    )
    if caller_current_refusals:
        status = "forbidden_caller_current_nonlocal_refusal"
    elif not page_map_first:
        status = "missing_page_map_first_source_routing"
    else:
        status = "page_map_first"
    structural_violation = bool(caller_current_refusals) or not page_map_first
    reachable_functions = sorted(
        (functions_by_node[node] for node in reachable),
        key=lambda function: (function.path, function.line, function.name),
    )
    return {
        "caller_current_nonlocal_refusals": caller_current_refusals,
        "evidence_kind": "syntactic selected-runtime realloc may-reachability",
        "final_acceptance": False,
        "function": entry.name,
        "page_map_first_source_routing": page_map_first,
        "page_map_lookup_matches": page_map_lookups,
        "reachable_functions": [function.identity() for function in reachable_functions],
        "source_routing_decisions": source_routing_decisions,
        "status": status,
        "structural_violation": structural_violation,
        "warning": (
            "This selected-source witness rejects the known caller-current nonlocal realloc "
            "refusal and requires a PageMap-first source-routing shape. It cannot prove "
            "dynamic realloc correctness, allocation/copy/free behavior, or final architecture acceptance."
        ),
    }


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
    cfg_environment = required_mapping(
        policy["cfg_environment"], "phase_bc_call_graph.cfg_environment"
    )
    functions = [
        function
        for path in policy["sources"]
        for function in selected_rust_functions(root, path, cfg_environment)
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
            "or promotion-qualified runtime completion."
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
    cfg_environment = required_mapping(
        phase_bc_policy(manifest)["cfg_environment"], "phase_bc_call_graph.cfg_environment"
    )
    found: dict[str, list[dict[str, object]]] = {}
    for name, raw_rule in required_mapping(forbidden["patterns"], "forbidden_scaffolding.patterns").items():
        rule = required_mapping(raw_rule, f"forbidden_scaffolding.patterns.{name}")
        matches = source_matches(
            root,
            required_string(rule.get("path"), f"forbidden_scaffolding.patterns.{name}.path"),
            required_string(rule.get("pattern"), f"forbidden_scaffolding.patterns.{name}.pattern"),
            cfg_environment,
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
    contract_path = root / required_string(
        contracts.get("canonical_upstream_stress"), "contracts.canonical_upstream_stress"
    )
    contract = read_json(contract_path)
    common: dict[str, object] = {
        "current_large_mode": False,
        "current_max_workers": 0,
        "required_final_large_mode": True,
        "required_final_max_workers": 8,
        "status": "unmet",
    }
    if (
        contract.get("format") != 5
        or contract.get("schema") != "crabc-mimalloc-canonical-upstream-stress"
    ):
        return {
            **common,
            "evidence_scope": None,
            "reason": "canonical upstream stress producer contract is not integrated",
            "report": None,
        }
    report_contract = required_mapping(contract.get("report"), "canonical stress report")
    report_path = root / required_string(report_contract.get("path"), "canonical stress report.path")
    try:
        report = read_json(report_path)
        workers, large_mode = validate_canonical_stress_report(
            root, manifest, contract_path, contract, report
        )
    except RatchetError as error:
        return {
            **common,
            "evidence_scope": required_mapping(
                contract.get("capability"), "canonical stress capability"
            ).get("evidence_scope"),
            "reason": str(error),
            "report": str(report_path),
        }
    return {
        "current_large_mode": large_mode,
        "current_max_workers": max(workers),
        "evidence_scope": required_mapping(
            contract.get("capability"), "canonical stress capability"
        ).get("evidence_scope"),
        "reason": None,
        "report": str(report_path),
        "required_final_large_mode": True,
        "required_final_max_workers": 8,
        "status": "verified",
        "warning": (
            "This canonical unmodified-source stress matrix is a bounded shadow-subset "
            "capability, not allocator promotion or large-object evidence."
        ),
    }


def exact_json(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, Mapping):
        assert isinstance(actual, Mapping)
        return set(actual) == set(expected) and all(
            exact_json(actual[name], value) for name, value in expected.items()
        )
    if isinstance(expected, list):
        assert isinstance(actual, list)
        return len(actual) == len(expected) and all(
            exact_json(left, right) for left, right in zip(actual, expected)
        )
    return actual == expected


def validate_byte_stream(record: object, expected: str, name: str) -> None:
    if not isinstance(record, Mapping) or set(record) != {"bytes", "hex", "sha256"}:
        raise RatchetError(f"canonical upstream stress {name} byte-stream record drifted")
    try:
        payload = bytes.fromhex(str(record["hex"]))
    except ValueError as error:
        raise RatchetError(f"canonical upstream stress {name} byte-stream hex is invalid") from error
    if (
        type(record["bytes"]) is not int
        or record["bytes"] != len(payload)
        or record["sha256"] != hashlib.sha256(payload).hexdigest()
    ):
        raise RatchetError(f"canonical upstream stress {name} byte-stream attestation drifted")
    try:
        observed = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RatchetError(f"canonical upstream stress {name} byte-stream is not UTF-8") from error
    if observed != expected:
        raise RatchetError(f"canonical upstream stress {name} byte-stream mismatched its case")


def validate_file_artifact(root: Path, record: object, name: str) -> dict[str, object]:
    if not isinstance(record, Mapping) or set(record) != {"bytes", "path", "sha256"}:
        raise RatchetError(f"canonical upstream stress {name} file-artifact record drifted")
    path_value = record.get("path")
    if not isinstance(path_value, str) or not path_value:
        raise RatchetError(f"canonical upstream stress {name} artifact path is invalid")
    path = Path(path_value)
    path = path if path.is_absolute() else root / path
    if (
        not path.is_file()
        or type(record.get("bytes")) is not int
        or record["bytes"] != path.stat().st_size
        or record.get("sha256") != sha256(path)
    ):
        raise RatchetError(f"canonical upstream stress {name} artifact bytes drifted")
    return dict(record)


def validate_canonical_stress_report(
    root: Path,
    manifest: Mapping[str, Any],
    contract_path: Path,
    contract: Mapping[str, Any],
    report: Mapping[str, Any],
) -> tuple[list[int], bool]:
    """Accept only the canonical producer's complete, attested native matrix."""

    report_contract = required_mapping(contract.get("report"), "canonical stress report")
    if report.get("format") != report_contract.get("format") or report.get("schema") != report_contract.get("schema"):
        raise RatchetError("canonical upstream stress report schema drifted")
    if report.get("status") != "passed":
        raise RatchetError("canonical upstream stress report did not pass")
    if report_contract.get("fixture_elf_fields") != [
        "dynamic_dependencies",
        "elf_identity",
        "interpreter",
    ]:
        raise RatchetError("canonical upstream stress fixture ELF report contract drifted")
    upstream = required_mapping(contract.get("upstream"), "canonical stress upstream")
    manifest_upstream = required_mapping(manifest.get("upstream"), "upstream")
    if upstream.get("version") != manifest_upstream.get("version") or upstream.get("revision") != manifest_upstream.get("revision"):
        raise RatchetError("canonical upstream stress uses a different mimalloc pin")
    expected_upstream_pin = {
        "archive_root": upstream.get("archive_root"),
        "repository": upstream.get("repository"),
        "revision": upstream.get("revision"),
        "sha256": upstream.get("archive_sha256"),
        "source": upstream.get("archive_source"),
        "tag": upstream.get("tag"),
        "tag_object": upstream.get("tag_object"),
        "version": upstream.get("version"),
    }
    if not all(isinstance(value, str) and value for value in expected_upstream_pin.values()):
        raise RatchetError("canonical upstream stress contract has incomplete upstream provenance")
    if not exact_json(report.get("upstream_pin"), expected_upstream_pin):
        raise RatchetError("canonical upstream stress report upstream provenance drifted")

    contract_record = required_mapping(report.get("contract"), "canonical stress report.contract")
    recorded_path = Path(required_string(contract_record.get("path"), "canonical stress report.contract.path"))
    recorded_path = recorded_path if recorded_path.is_absolute() else root / recorded_path
    if recorded_path.resolve() != contract_path.resolve():
        raise RatchetError("canonical upstream stress report names a different contract artifact")
    if not contract_path.is_file():
        raise RatchetError("canonical upstream stress contract artifact is absent")
    if (
        contract_record.get("bytes") != contract_path.stat().st_size
        or contract_record.get("sha256") != sha256(contract_path)
        or not exact_json(contract_record.get("upstream"), upstream)
    ):
        raise RatchetError("canonical upstream stress contract artifact attestation drifted")

    adaptation = required_mapping(contract.get("source_adaptation"), "canonical stress adaptation")
    if adaptation.get("patches") != [] or adaptation.get("kind") != "upstream-preprocessor-symbol-selection-only":
        raise RatchetError("canonical upstream stress source is adapted outside upstream symbol selection")
    backend_inventory = required_mapping(contract.get("backend_inventory"), "canonical stress backend")
    backend_id = required_string(backend_inventory.get("selected"), "canonical stress selected backend")
    backends = backend_inventory.get("backends")
    selected_backends = [
        item for item in backends if isinstance(item, Mapping) and item.get("id") == backend_id
    ] if isinstance(backends, list) else []
    if len(selected_backends) != 1 or selected_backends[0].get("allocator_feature") != "native-mimalloc-shadow" or selected_backends[0].get("c_backend_fallback") is not False:
        raise RatchetError("canonical upstream stress did not select the native Rust backend")
    backend_attestation_contract = required_mapping(
        selected_backends[0].get("artifact_attestation"),
        "canonical stress backend artifact attestation",
    )
    cargo_artifact_contract = required_mapping(
        backend_attestation_contract.get("cargo_compiler_artifact"),
        "canonical stress Cargo compiler-artifact",
    )
    expected_cargo_command = [
        "cargo",
        "build",
        "-p",
        "crabc-libc",
        "--features",
        "native-mimalloc-shadow",
        "--profile",
        "dev",
        "--message-format=json-render-diagnostics",
    ]
    if (
        cargo_artifact_contract.get("build_record_format") != 1
        or cargo_artifact_contract.get("build_record_schema")
        != "crabc-selected-libc-cargo-build"
        or cargo_artifact_contract.get("cargo_command") != expected_cargo_command
        or cargo_artifact_contract.get("semantic_profile") != "dev"
        or cargo_artifact_contract.get("exact_features")
        != ["default", "native-mimalloc-shadow"]
        or cargo_artifact_contract.get("artifacts")
        != {
            "selected_shared_libc": "libc.so",
            "selected_static_libc": "libc.a",
        }
    ):
        raise RatchetError("canonical upstream stress Cargo build-record contract drifted")
    target_inventory = required_mapping(contract.get("target_inventory"), "canonical stress target")
    target_id = required_string(target_inventory.get("selected"), "canonical stress selected target")
    targets = target_inventory.get("targets")
    selected_targets = [
        item for item in targets if isinstance(item, Mapping) and item.get("id") == target_id
    ] if isinstance(targets, list) else []
    if len(selected_targets) != 1 or selected_targets[0].get("status") != "applicable":
        raise RatchetError("canonical upstream stress did not select its native target")
    expected_selection = {"backend": backend_id, "target": dict(selected_targets[0])}
    if not exact_json(report.get("selection"), expected_selection):
        raise RatchetError("canonical upstream stress report selection provenance drifted")

    report_artifacts = required_mapping(
        report.get("artifacts"), "canonical stress report.artifacts"
    )
    artifact_ids = required_mapping(contract.get("report"), "canonical stress report").get(
        "artifact_ids"
    )
    if (
        not isinstance(artifact_ids, list)
        or set(report_artifacts) != set(artifact_ids)
    ):
        raise RatchetError("canonical upstream stress report artifact inventory drifted")
    build_record = validate_file_artifact(
        root,
        report_artifacts.get("selected_backend_build_record"),
        "selected backend build record",
    )
    shared_libc = validate_file_artifact(
        root, report_artifacts.get("selected_libc"), "selected shared libc"
    )
    static_libc = validate_file_artifact(
        root, report_artifacts.get("selected_static_libc"), "selected static libc"
    )
    runtime = required_mapping(report.get("runtime"), "canonical stress report.runtime")
    backend_attestation = required_mapping(
        runtime.get("backend_attestation"),
        "canonical stress report.runtime.backend_attestation",
    )
    compiler_artifact = required_mapping(
        backend_attestation.get("compiler_artifact"),
        "canonical stress report compiler-artifact",
    )
    expected_artifacts = {
        "selected_shared_libc": shared_libc,
        "selected_static_libc": static_libc,
    }
    exported_route = required_mapping(
        backend_attestation.get("exported_free"),
        "canonical stress report exported free route",
    )
    route_contract = required_mapping(
        backend_attestation_contract.get("exported_free_route"),
        "canonical stress exported free route contract",
    )
    if (
        backend_attestation.get("backend") != backend_id
        or backend_attestation.get("status") != "passed"
        or backend_attestation.get("semantic_profile") != "dev"
        or backend_attestation.get("cargo_features")
        != cargo_artifact_contract.get("exact_features")
        or not exact_json(backend_attestation.get("build_record"), build_record)
        or not exact_json(backend_attestation.get("artifacts"), expected_artifacts)
        or compiler_artifact.get("profile") != cargo_artifact_contract.get("profile")
        or compiler_artifact.get("target") != cargo_artifact_contract.get("target")
        or compiler_artifact.get("features") != cargo_artifact_contract.get("exact_features")
        or compiler_artifact.get("filenames")
        != [shared_libc["path"], static_libc["path"]]
        or type(compiler_artifact.get("fresh")) is not bool
        or exported_route.get("symbol") != route_contract.get("symbol")
        or exported_route.get("required_callee_suffix")
        != route_contract.get("required_callee_suffix")
        or exported_route.get("forbidden_callee_suffix")
        != route_contract.get("forbidden_callee_suffix")
        or not isinstance(exported_route.get("disassembly_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", exported_route["disassembly_sha256"])
        is None
    ):
        raise RatchetError("canonical upstream stress backend artifact attestation drifted")

    compile_requirements = required_mapping(
        contract.get("compile_requirements"), "canonical stress compile requirements"
    )
    expected_fixture_elf = {
        "dynamic_dependencies": compile_requirements.get("expected_dynamic_dependencies"),
        "elf_identity": compile_requirements.get("expected_elf_identity"),
        "interpreter": compile_requirements.get("expected_interpreter"),
    }
    if not exact_json(report.get("fixture_elf"), expected_fixture_elf):
        raise RatchetError("canonical upstream stress fixture ELF provenance drifted")
    if not exact_json(
        report.get("dynamic_dependencies"), expected_fixture_elf["dynamic_dependencies"]
    ):
        raise RatchetError("canonical upstream stress dynamic dependency provenance drifted")

    execution_contract = required_mapping(contract.get("execution"), "canonical stress execution")
    matrix = execution_contract.get("matrix")
    if not isinstance(matrix, list) or len(matrix) != 8 or not all(isinstance(case, Mapping) for case in matrix):
        raise RatchetError("canonical upstream stress contract does not contain the eight-case matrix")
    case_ids = [case.get("id") for case in matrix]
    if not all(isinstance(case_id, str) and case_id for case_id in case_ids) or len(set(case_ids)) != len(case_ids):
        raise RatchetError("canonical upstream stress matrix case identities are invalid")
    workers = sorted({case.get("workers") for case in matrix if type(case.get("workers")) is int})
    if workers != [1, 2, 4, 8] or any(
        case.get("arguments") != [str(case.get("workers")), str(case.get("scale")), str(case.get("iterations"))]
        for case in matrix
    ):
        raise RatchetError("canonical upstream stress matrix is not the required 1/2/4/8 source-argument matrix")
    if execution_contract.get("process_attempts_per_case") != 1 or execution_contract.get("stop_after_first_nonpass") is not True:
        raise RatchetError("canonical upstream stress execution policy drifted")

    execution = required_mapping(report.get("execution"), "canonical stress report.execution")
    results = execution.get("case_results")
    if (
        execution.get("attempted") is not True
        or execution.get("attempted_process_count") != len(matrix)
        or execution.get("case_count") != len(matrix)
        or execution.get("process_attempts_per_case") != 1
        or not isinstance(results, list)
        or len(results) != len(matrix)
    ):
        raise RatchetError("canonical upstream stress report contains a partial matrix")
    inventory_fields = ("id", "workers", "scale", "iterations", "arguments")
    for attempt, (case, result) in enumerate(zip(matrix, results), start=1):
        expected_case = {name: case.get(name) for name in inventory_fields}
        if not isinstance(result, Mapping) or result.get("state") != "passed" or result.get("process_attempt") != attempt or not exact_json(result.get("case"), expected_case):
            raise RatchetError("canonical upstream stress report case order or state drifted")
        observation = required_mapping(result.get("observation"), "canonical stress case observation")
        command = observation.get("command")
        if (
            observation.get("kind") != "process"
            or observation.get("status") != case.get("expected_exit_status")
            or not isinstance(command, list)
            or command[1:] != case.get("arguments")
        ):
            raise RatchetError("canonical upstream stress report lacks real process provenance")
        validate_byte_stream(observation.get("stdout"), str(case.get("expected_stdout")), "stdout")
        validate_byte_stream(observation.get("stderr"), str(case.get("expected_stderr")), "stderr")

    capability_contract = required_mapping(contract.get("capability"), "canonical stress capability")
    required_workers = capability_contract.get("required_worker_counts")
    capability = required_mapping(report.get("capability"), "canonical stress report.capability")
    expected_capability = {
        "failure_closed": True,
        "fully_verified_worker_counts": required_workers,
        "id": capability_contract.get("id"),
        "native_execution_completed": True,
        "native_execution_started": True,
        "passed_case_count": len(matrix),
        "required_case_count": len(matrix),
        "required_worker_counts": required_workers,
        "status": "passed",
    }
    if not exact_json(capability, expected_capability):
        raise RatchetError("canonical upstream stress capability did not complete exactly")
    if not exact_json(
        report.get("first_fact"),
        {"completed_case_count": len(matrix), "kind": "pass", "stage": "matrix"},
    ):
        raise RatchetError("canonical upstream stress report does not record its complete matrix fact")
    large_mode = required_mapping(
        execution_contract.get("large_object_mode"), "canonical stress large-object mode"
    ).get("status") == "passed"
    return workers, large_mode


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
    root: Path = ROOT,
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
    selection = evidence.get("selected_production")
    if not isinstance(selection, Mapping) or selection.get("feature") != selected.get("feature"):
        raise RatchetError("runtime/artifact evidence does not describe the selected native feature")
    if selection.get("source_sha256") != selected.get("sources"):
        raise RatchetError("runtime/artifact evidence does not match the selected source metadata")
    artifact = evidence.get("artifact")
    if not isinstance(artifact, Mapping) or not isinstance(artifact.get("path"), str) or not artifact.get("path"):
        raise RatchetError("runtime/artifact evidence does not identify a selected artifact")
    artifact_digest = artifact.get("sha256")
    if not isinstance(artifact_digest, str) or re.fullmatch(r"[0-9a-f]{64}", artifact_digest) is None:
        raise RatchetError("runtime/artifact evidence has no selected artifact SHA-256")
    artifact_path = Path(artifact["path"])
    artifact_path = artifact_path if artifact_path.is_absolute() else root / artifact_path
    if not artifact_path.is_file() or artifact_path.is_symlink():
        raise RatchetError("runtime/artifact evidence selected artifact is absent")
    observed_artifact_digest = sha256(artifact_path)
    if observed_artifact_digest != artifact_digest:
        raise RatchetError("runtime/artifact evidence artifact SHA-256 mismatch")
    metrics = evidence.get("metrics")
    if not isinstance(metrics, Mapping):
        raise RatchetError("runtime/artifact evidence does not record metrics")
    if manifest is None:
        raise RatchetError("runtime/artifact evidence validation requires the architecture manifest")
    scope = evidence.get("evidence_scope")
    required_scope = required_string(
        required_mapping(manifest.get("scope"), "scope").get("final_required"),
        "scope.final_required",
    )
    if scope != required_scope:
        raise RatchetError(
            f"runtime/artifact evidence must have the manifest's exact final scope: {required_scope}"
        )
    required_phase_bc = required_mapping(
        phase_bc_policy(manifest).get("runtime_evidence_required"),
        "phase_bc_call_graph.runtime_evidence_required",
    )
    phase_bc = evidence.get("phase_bc")
    required_evidence_shape(phase_bc, required_phase_bc, "phase_bc")
    runtime_contract = required_mapping(manifest.get("runtime_evidence"), "runtime_evidence")
    producer = required_mapping(
        runtime_contract.get("promotion_benchmark_producer"),
        "runtime_evidence.promotion_benchmark_producer",
    )
    producer_schema = producer.get("schema")
    if producer_schema is None:
        raise RatchetError(
            "no reviewed promotion benchmark producer schema is registered; "
            "status strings are not benchmark samples or provenance"
        )
    raise RatchetError(f"unsupported promotion benchmark producer schema: {producer_schema}")


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
    reallocate_dispatch = report["native_reallocate_pointer_first_dispatch"]
    if reallocate_dispatch["structural_violation"]:
        unmet.append("native_reallocate caller-current nonlocal refusal")
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
        unmet.append("promotion-qualified runtime/artifact evidence")
    else:
        evidence = runtime["evidence"]
        metrics = evidence["metrics"]
        for name, metric in report["metrics"].items():
            if name in PROMOTION_BENCHMARK_METRICS:
                continue
            if metrics.get(name) != metric["final_required"]:
                unmet.append(f"runtime evidence {name}")
        for name in PROMOTION_BENCHMARK_METRICS:
            unmet.append(f"runtime evidence {name} lacks validated benchmark samples/provenance")
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
    reallocate_dispatch = native_reallocate_pointer_first_dispatch(root, manifest)
    phase_bc = phase_bc_selected_production_reachability(root, manifest)
    runtime = load_runtime_evidence(runtime_evidence_path, selected, manifest, root)
    report: dict[str, object] = {
        "format": 1,
        "schema": "crabc-mimalloc-architecture-ratchet-report",
        "scope": required_mapping(manifest["scope"], "scope"),
        "selected_production": selected,
        "metrics": metrics,
        "caller_identity_first_free_dispatch": caller_dispatch,
        "native_reallocate_pointer_first_dispatch": reallocate_dispatch,
        "phase_bc_selected_production_reachability": phase_bc,
        "forbidden_scaffolding_compiled": collect_forbidden_scaffolding(root, manifest),
        "unmodified_upstream_stress": upstream_stress_capability(root, manifest),
        "runtime_artifact_evidence": runtime,
        "ratchet": {
            "regressions": sorted(
                [*ratchet_regressions(manifest, signals), *phase_bc["regressions"]]
            )
        },
        "structural_violations": [
            *(
                ["caller-identity-first native_free dispatch"]
                if caller_dispatch["structural_violation"]
                else []
            ),
            *(
                ["native_reallocate caller-current nonlocal refusal"]
                if reallocate_dispatch["structural_violation"]
                else []
            ),
        ],
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
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    staged: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            staged = Path(stream.name)
        os.replace(staged, path)
        staged = None
    finally:
        if staged is not None:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass


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
