"""Closed search, hash, and application-DSO contracts for dynamic receipts.

Schema 1 is a read-only compatibility form. Schema 2 is the current direct
link form: every declared application DSO is an LLD input. Schema 3 is an
explicit opt-in closure form. It keeps the complete DSO identity map, records
each node's direct or transitive role and DT_NEEDED edges, and marks every
receipt input as either an actual linker input or a validation-only transitive
DSO. A reader must request that newer contract deliberately; ordinary zero-DSO
consumers continue to accept only schemas 1 and 2.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path
from typing import Any, Callable, Mapping


V1_FIELDS = frozenset({
    "schema", "format", "mode", "binding", "runtime_imports", "application_runpath", "output_path",
    "output_sha256", "manifest_sha256", "application_dsos", "owned_runtime_inputs", "input_receipts",
    "resolved_linker", "link_command", "link_trace", "campaign_complete",
})
V2_FIELDS = V1_FIELDS | {
    "application_search_kind", "application_rpath", "application_hash_style",
}
V3_FIELDS = V2_FIELDS | {
    "application_dso_roles", "application_dso_needed",
}

_APPLICATION_DSO_BASENAME = re.compile(r"[^/\x00]+\.so(?:\.[0-9]+)*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_INPUT_ROLES = frozenset({
    "linker-input", "direct-application-dso", "transitive-application-dso",
})
RESERVED_APPLICATION_DSO_NAMES = frozenset({
    "libc.so", "ld-crabc-x86_64.so.1", "ld-musl-x86_64.so.1",
})


def is_reserved_application_dso_name(name: object) -> bool:
    """Whether an application-node name conflicts with an owned runtime identity."""

    return type(name) is str and name in RESERVED_APPLICATION_DSO_NAMES


@dataclass(frozen=True)
class ApplicationDso:
    """One schema-3 closure node, bound to a physical validation input."""

    name: str
    path: str
    sha256: str
    role: str
    needed: tuple[str, ...]


@dataclass(frozen=True)
class SearchContract:
    """Normalized schema-specific search/hash facts and optional DSO closure."""

    schema: int
    kind: str
    path: str
    hash_style: str
    application_dso_closure: tuple[ApplicationDso, ...] = ()


def _require(condition: bool, message: str, fail: Callable[[str], None]) -> None:
    if not condition:
        fail(message)
        raise AssertionError("dynamic receipt failure callback returned")


def _application_closure(
    record: Mapping[str, Any], *, label: str, fail: Callable[[str], None]
) -> tuple[ApplicationDso, ...]:
    """Validate the typed schema-3 closure without assuming an acyclic graph."""

    identities = record["application_dsos"]
    roles = record["application_dso_roles"]
    edges = record["application_dso_needed"]
    _require(type(identities) is dict, f"{label} application DSO identities are invalid", fail)
    _require(type(roles) is dict and type(edges) is dict, f"{label} application DSO closure is invalid", fail)

    names = set(identities)
    _require(names == set(roles) == set(edges), f"{label} application DSO closure keysets differ", fail)
    _require(names, f"{label} application DSO closure is empty", fail)
    for name, digest in identities.items():
        _require(type(name) is str and _APPLICATION_DSO_BASENAME.fullmatch(name) is not None,
                 f"{label} application DSO identity is invalid", fail)
        _require(not is_reserved_application_dso_name(name),
                 f"{label} application DSO name is reserved", fail)
        _require(type(digest) is str and _SHA256.fullmatch(digest) is not None,
                 f"{label} application DSO identity is invalid", fail)

    direct: set[str] = set()
    for name in names:
        role = roles[name]
        _require(type(role) is str and role in ("direct", "transitive"),
                 f"{label} application DSO role is invalid", fail)
        if role == "direct":
            direct.add(name)
        needed = edges[name]
        _require(type(needed) is list and all(type(item) is str for item in needed),
                 f"{label} application DSO edges are invalid", fail)
        _require(len(set(needed)) == len(needed), f"{label} application DSO edges are duplicated", fail)
        _require(all(item == "libc.so" or item in names for item in needed),
                 f"{label} application DSO closure has a missing node", fail)
    _require(direct and len(direct) < len(names),
             f"{label} application DSO closure must contain direct and transitive roles", fail)

    reachable: set[str] = set()
    pending = list(direct)
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        reachable.add(name)
        pending.extend(item for item in edges[name] if item in names and item not in reachable)
    _require(reachable == names, f"{label} application DSO closure has an unreachable node", fail)

    records = record["input_receipts"]
    _require(type(records) is list, f"{label} typed input receipts are invalid", fail)
    bound: dict[str, tuple[str, str, str]] = {}
    paths: set[str] = set()
    for item in records:
        _require(type(item) is dict and type(item.get("role")) is str
                 and item["role"] in _INPUT_ROLES,
                 f"{label} typed input receipt role is invalid", fail)
        role = item["role"]
        expected_keys = {"role", "path", "sha256"}
        if role != "linker-input":
            expected_keys.add("name")
        _require(set(item) == expected_keys, f"{label} typed input receipt fields are invalid", fail)
        path, digest = item["path"], item["sha256"]
        _require(type(path) is str and path and "\0" not in path and type(digest) is str
                 and _SHA256.fullmatch(digest) is not None,
                 f"{label} typed input receipt identity is invalid", fail)
        _require(path not in paths, f"{label} typed input receipt path is duplicated", fail)
        paths.add(path)
        if role == "linker-input":
            continue
        name = item["name"]
        _require(type(name) is str and name in names and Path(path).name == name,
                 f"{label} typed application DSO input name is invalid", fail)
        _require(name not in bound, f"{label} typed application DSO input is duplicated", fail)
        bound[name] = (role, path, digest)

    _require(set(bound) == names, f"{label} typed application DSO inputs do not close the graph", fail)
    command = record["link_command"]
    trace = record["link_trace"]
    _require(type(command) is list and all(type(item) is str for item in command),
             f"{label} schema-3 link command is invalid", fail)
    _require(type(trace) is list and all(type(item) is str for item in trace),
             f"{label} schema-3 link trace is invalid", fail)
    closure: list[ApplicationDso] = []
    for name in sorted(names):
        role, path, digest = bound[name]
        expected_role = roles[name] + "-application-dso"
        _require(role == expected_role and digest == identities[name],
                 f"{label} typed application DSO input role or identity differs", fail)
        if roles[name] == "direct":
            _require(command.count(path) == 1 and trace.count(path) == 1,
                     f"{label} direct application DSO is not an exact linker input", fail)
        else:
            _require(path not in command and path not in trace,
                     f"{label} transitive application DSO reached the linker", fail)
        closure.append(ApplicationDso(name, path, identities[name], roles[name], tuple(edges[name])))
    return tuple(closure)


def validate(
    record: Mapping[str, Any], *, format: str, label: str, fail: Callable[[str], None],
    allow_application_dso_closure: bool = False,
) -> SearchContract:
    """Require one exact declared schema and normalize its search facts.

    Schema-3 readers must explicitly opt into its DSO graph semantics. This
    avoids silently widening an existing consumer that intentionally accepts
    only an executable with no application DSO closure.
    """

    schema = record.get("schema")
    if type(schema) is not int or schema not in (1, 2, 3):
        fail(f"{label} has no supported declared schema")
        raise AssertionError("dynamic receipt failure callback returned")
    expected = V1_FIELDS if schema == 1 else V2_FIELDS if schema == 2 else V3_FIELDS
    _require(set(record) == expected, f"{label} fields do not match declared schema {schema}", fail)
    _require(record["format"] == format, f"{label} format differs", fail)

    closure: tuple[ApplicationDso, ...] = ()
    if schema == 3:
        _require(allow_application_dso_closure,
                 f"{label} does not admit an application DSO closure", fail)
        closure = _application_closure(record, label=label, fail=fail)

    if schema == 1:
        path = record["application_runpath"]
        _require(type(path) is str and path and "\0" not in path,
                 f"{label} legacy RUNPATH is invalid", fail)
        return SearchContract(schema=1, kind="runpath", path=path, hash_style="sysv")

    kind = record["application_search_kind"]
    hash_style = record["application_hash_style"]
    runpath = record["application_runpath"]
    rpath = record["application_rpath"]
    _require(kind in ("runpath", "rpath"), f"{label} search kind is invalid", fail)
    _require(hash_style in ("sysv", "gnu", "both"), f"{label} hash style is invalid", fail)
    if kind == "runpath":
        _require(type(runpath) is str and runpath and "\0" not in runpath and rpath is None,
                 f"{label} RUNPATH fields are invalid", fail)
        path = runpath
    else:
        _require(type(rpath) is str and rpath and "\0" not in rpath and runpath is None,
                 f"{label} RPATH fields are invalid", fail)
        path = rpath
    return SearchContract(schema=schema, kind=kind, path=path, hash_style=hash_style,
                          application_dso_closure=closure)


def require_runpath(
    contract: SearchContract, path: str, *, label: str, fail: Callable[[str], None], hash_style: str = "sysv"
) -> None:
    """Require the bounded RUNPATH/hash configuration used by one workload."""

    if (contract.kind, contract.path, contract.hash_style) != ("runpath", path, hash_style):
        fail(f"{label} search-path or hash-style state drifted")
