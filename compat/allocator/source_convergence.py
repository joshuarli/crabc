#!/usr/bin/env python3
"""Structural reader for source-faithful convergence of the Rust mimalloc port.

plan.md's M9 row requires "source-faithful convergence"; AGENTS.md requires
the port to preserve source algorithms, data structures, ownership, memory
ordering and lifecycle, and gives any algorithmic divergence "a durable
rationale plus differential and performance evidence". This reader turns
that into conditions over the existing manifests only, never over prose:

* ``pin``: ``compat/allocator/port-map.toml`` names the pinned upstream
  version and revision of ``compat/upstreams.toml``, and
  ``crabc-mimalloc/UPSTREAM.md`` records that revision.
* ``implemented``: every port-map unit and item is implemented,
  unit-verified and differential-verified.
* ``transitional``: no port-map row's ``rust_item`` is ``unimplemented`` or
  ``partial: ...``.
* ``intentional-differences``: every row whose ``difference_kind`` is
  ``algorithmic`` (its ``intentional_difference`` is the rationale) is also
  differential-verified and performance-qualified; ``run.py --check`` owns
  the field's schema. ``boundary`` rows are scope, representation,
  integration-owner or fail-closed notes and need no such evidence.
* ``known-differences``: every ``### `` entry of ``known-differences.md``
  has a stable backticked identifier and one of the register's closed
  statuses (``accepted`` or ``rejected``; ``observed`` and ``pending`` are
  open by the register's own entry requirements). Each accepted identifier
  is carried by at least one port-map row, whose flags are its evidence:
  either the row's ``intentional_difference`` names it, or the entry's one
  ``- **Port map:** `upstream:name`, ...`` line names existing rows.

Each condition names every failing row or entry; ``--summary`` prints counts.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
PORT_MAP = ROOT / "compat/allocator/port-map.toml"
KNOWN_DIFFERENCES = ROOT / "compat/allocator/known-differences.md"
UPSTREAM = ROOT / "crabc-mimalloc/UPSTREAM.md"
UPSTREAMS = ROOT / "compat/upstreams.toml"
REQUIRED_FLAGS = ("implemented", "unit_verified", "differential_verified")
DIFFERENCE_EVIDENCE_FLAGS = ("differential_verified", "performance_qualified")
CLOSED_STATUSES = ("accepted", "rejected")
ENTRY = re.compile(r"^### (?:`(?P<id>[A-Z0-9-]+)`\s*(?:—|-)\s*(?P<status>\S+))?(?P<rest>.*)$")
IDENTIFIER = re.compile(r"CRABC-[A-Z0-9-]+")


def row_label(row: Mapping[str, Any]) -> str:
    return f"{row.get('upstream')}:{row.get('name') or row.get('source_region')}"


def port_map_rows(port_map: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [dict(row, kind=kind) for kind in ("unit", "item") for row in port_map.get(kind, [])]


CARRIER = re.compile(r"^- \*\*Port map:\*\* (?P<refs>.+)$")


def known_difference_entries(text: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("## "):
            entries.append({"section": True})
        if not line.startswith("### "):
            carrier = CARRIER.match(line)
            if carrier and entries and not entries[-1].get("section"):
                entries[-1]["carriers"].append(re.findall(r"`([^`]+)`", carrier.group("refs")))
            continue
        match = ENTRY.match(line)
        entries.append({"line": number, "heading": line[4:].strip(),
                        "id": match.group("id") if match else None,
                        "status": match.group("status") if match else None, "carriers": []})
    return [entry for entry in entries if not entry.get("section")]


def conditions(port_map: Mapping[str, Any], known_differences: str, upstream: str,
               pin: Mapping[str, str]) -> list[dict[str, Any]]:
    rows = port_map_rows(port_map)
    metadata = port_map.get("metadata", {})

    pin_unmet = []
    if (metadata.get("upstream_version"), metadata.get("upstream_revision")) != (pin["version"], pin["revision"]):
        pin_unmet.append(f"port-map names {metadata.get('upstream_version')}/{metadata.get('upstream_revision')}, "
                         f"not the pinned {pin['version']}/{pin['revision']}")
    if pin["revision"] not in upstream:
        pin_unmet.append("crabc-mimalloc/UPSTREAM.md does not record the pinned revision")

    implemented = [f"{row_label(row)} lacks {', '.join(flag for flag in REQUIRED_FLAGS if row.get(flag) is not True)}"
                   for row in rows if not all(row.get(flag) is True for flag in REQUIRED_FLAGS)]
    transitional = [f"{row_label(row)} is {row['rust_item'].split(':', 1)[0]}" for row in rows
                    if row.get("rust_item") == "unimplemented" or str(row.get("rust_item", "")).startswith("partial")]
    differences = [f"{row_label(row)} has no difference_kind" for row in rows if "difference_kind" not in row]
    differences += [
        f"{row_label(row)} states an algorithmic divergence without "
        f"{', '.join(flag for flag in DIFFERENCE_EVIDENCE_FLAGS if row.get(flag) is not True)}"
        for row in rows
        if row.get("difference_kind") == "algorithmic"
        and not all(row.get(flag) is True for flag in DIFFERENCE_EVIDENCE_FLAGS)
    ]

    carried = {identifier for row in rows for identifier in IDENTIFIER.findall(str(row.get("intentional_difference", "")))}
    row_keys = {row["upstream"] if row["kind"] == "unit" else f"{row['upstream']}:{row.get('name')}" for row in rows}
    register = []
    for entry in known_difference_entries(known_differences):
        where = f"known-differences.md:{entry['line']}"
        if entry["id"] is None:
            if not entry["heading"].startswith("`"):
                register.append(f"{where} entry {entry['heading']!r} has no stable identifier")
            continue
        status = (entry["status"] or "").strip("*`")
        named = [ref for line in entry["carriers"] for ref in line]
        unknown = [ref for ref in named if ref not in row_keys]
        if len(entry["carriers"]) > 1:
            register.append(f"{where} {entry['id']} has more than one Port map line")
        if unknown:
            register.append(f"{where} {entry['id']} names absent port-map rows {unknown}")
        if status not in CLOSED_STATUSES:
            register.append(f"{where} {entry['id']} is {status!r}, not {' or '.join(CLOSED_STATUSES)}")
        elif status == "accepted" and entry["id"] not in carried and not (named and not unknown):
            register.append(f"{where} accepted {entry['id']} is carried by no port-map row's evidence flags")

    def condition(identifier: str, unmet: Sequence[str], detail: str) -> dict[str, Any]:
        return {"id": identifier, "met": not unmet, "detail": list(unmet) if unmet else detail}

    return [
        condition("pin", pin_unmet, f"port-map and UPSTREAM.md name {pin['version']} {pin['revision']}"),
        condition("implemented", implemented, f"{len(rows)} port-map rows implemented and verified"),
        condition("transitional", transitional, "no port-map row is partial or unimplemented"),
        condition("intentional-differences", differences, "every algorithmic divergence has its evidence flags"),
        condition("known-differences", register, "every register entry is closed and carried"),
    ]


def load_pin() -> dict[str, str]:
    with UPSTREAMS.open("rb") as stream:
        mimalloc = tomllib.load(stream)["mimalloc"]
    return {"version": str(mimalloc["version"]).removeprefix("v"), "revision": mimalloc["revision"]}


def evaluate(root: Path = ROOT) -> list[dict[str, Any]]:
    if Path(root).resolve() != ROOT.resolve():
        raise RuntimeError(f"source convergence must be read by the checkout that owns this reader: {root}")
    with PORT_MAP.open("rb") as stream:
        port_map = tomllib.load(stream)
    return conditions(port_map, KNOWN_DIFFERENCES.read_text(encoding="utf-8"),
                      UPSTREAM.read_text(encoding="utf-8"), load_pin())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--summary", action="store_true", help="print one count per condition")
    arguments = parser.parse_args(argv)
    result = evaluate()
    if arguments.summary:
        for row in result:
            print(f"{row['id']}: {'met' if row['met'] else f'unmet ({len(row['detail'])})'}")
    else:
        print(json.dumps(result, indent=2))
    return 0 if all(row["met"] for row in result) else 1


if __name__ == "__main__":
    sys.exit(main())
