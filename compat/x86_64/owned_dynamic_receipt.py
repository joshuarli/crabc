"""Closed versioned search and hash fields for owned dynamic link receipts.

Schema 1 is retained only to read previously materialized receipts.  It has
the historical exact field roster, represents RUNPATH through
``application_runpath``, and predates selectable hash styles, so its hash
style is implicitly SysV.  Current driver output is schema 2: it records the
search kind, gives RUNPATH and RPATH separate fields, and always records the
selected hash style.  Consumers must choose one declared schema; mixed
schema-1/new-field records and unversioned records are invalid.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


V1_FIELDS = frozenset({
    "schema", "format", "mode", "binding", "runtime_imports", "application_runpath", "output_path",
    "output_sha256", "manifest_sha256", "application_dsos", "owned_runtime_inputs", "input_receipts",
    "resolved_linker", "link_command", "link_trace", "campaign_complete",
})
V2_FIELDS = V1_FIELDS | {
    "application_search_kind", "application_rpath", "application_hash_style",
}


@dataclass(frozen=True)
class SearchContract:
    """Normalized schema-specific search and hash facts for one receipt."""

    schema: int
    kind: str
    path: str
    hash_style: str


def validate(
    record: Mapping[str, Any], *, format: str, label: str, fail: Callable[[str], None]
) -> SearchContract:
    """Require one exact declared receipt schema and normalize its search facts."""

    schema = record.get("schema")
    if type(schema) is not int or schema not in (1, 2):
        fail(f"{label} has no supported declared schema")
    expected = V1_FIELDS if schema == 1 else V2_FIELDS
    if set(record) != expected:
        fail(f"{label} fields do not match declared schema {schema}")
    if record["format"] != format:
        fail(f"{label} format differs")

    if schema == 1:
        path = record["application_runpath"]
        if not isinstance(path, str) or not path or "\0" in path:
            fail(f"{label} legacy RUNPATH is invalid")
        return SearchContract(schema=1, kind="runpath", path=path, hash_style="sysv")

    kind = record["application_search_kind"]
    hash_style = record["application_hash_style"]
    runpath = record["application_runpath"]
    rpath = record["application_rpath"]
    if kind not in ("runpath", "rpath"):
        fail(f"{label} search kind is invalid")
    if hash_style not in ("sysv", "gnu", "both"):
        fail(f"{label} hash style is invalid")
    if kind == "runpath":
        if not isinstance(runpath, str) or not runpath or "\0" in runpath or rpath is not None:
            fail(f"{label} RUNPATH fields are invalid")
        path = runpath
    else:
        if not isinstance(rpath, str) or not rpath or "\0" in rpath or runpath is not None:
            fail(f"{label} RPATH fields are invalid")
        path = rpath
    return SearchContract(schema=2, kind=kind, path=path, hash_style=hash_style)


def require_runpath(
    contract: SearchContract, path: str, *, label: str, fail: Callable[[str], None], hash_style: str = "sysv"
) -> None:
    """Require the bounded RUNPATH/hash configuration used by one workload."""

    if (contract.kind, contract.path, contract.hash_style) != ("runpath", path, hash_style):
        fail(f"{label} search-path or hash-style state drifted")
