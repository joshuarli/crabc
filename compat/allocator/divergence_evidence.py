#!/usr/bin/env python3
"""Differential and performance evidence for every algorithmic divergence.

``divergence-evidence-v3.5.0.json`` gives each port-map row whose
``difference_kind`` is ``algorithmic`` one entry, and ``--check`` requires
the two sets to match exactly. An entry is either owned by the lane porting
the row back to the source algorithm, or names:

* ``differential``: an allocator-container command whose success is the
  C/Rust differential, or ``not_applicable`` with the reason;
* ``performance``: ``integrated_rows`` that a qualified
  ``perf_integrated_x86_64`` report must measure, ``engine_rows`` that a
  qualified engine report must measure, ``not_applicable`` with the reason,
  or ``blocked`` naming what is missing.

``not_applicable`` is admitted only where pinned C has no valid-program
behavior to compare: both kinds must be ``not_applicable`` with nonempty
reasons, and the entry's ``c_defect`` must name the pinned C source lines
where C faults or has undefined behavior plus the accepted
``known-differences.md`` entry that records the defect and is carried by
this row. Such an entry stands in for the row's evidence flags in the
source-convergence reader; nothing else may use ``not_applicable``.

The default run executes each differential and reads the qualified reports,
then names every row whose evidence is incomplete. It never changes the
port-map evidence flags: an owner sets those after this run passes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "compat/allocator/divergence-evidence-v3.5.0.json"
PORT_MAP = ROOT / "compat/allocator/port-map.toml"
KNOWN_DIFFERENCES = ROOT / "compat/allocator/known-differences.md"
C_DEFECT_LINE = re.compile(r"^(?:src|include)/[A-Za-z0-9_/.-]+\.[ch]:\d+(?:-\d+)?$")
SCHEMA = "crabc-mimalloc-divergence-evidence"


class EvidenceError(RuntimeError):
    """The evidence manifest does not describe the algorithmic rows."""


def algorithmic_rows(port_map: Mapping[str, Any]) -> list[str]:
    rows = []
    for kind in ("unit", "item"):
        for row in port_map.get(kind, []):
            if row.get("difference_kind") == "algorithmic":
                rows.append(row["upstream"] if kind == "unit" else f"{row['upstream']}:{row['name']}")
    return sorted(rows)


def not_applicable_unmet(key: str, entry: Mapping[str, Any], port_map: Mapping[str, Any],
                         register_text: str) -> list[str]:
    """Why a not_applicable entry is not admissible; empty when it is (or does not use not_applicable)."""

    import source_convergence

    kinds = [name for name in ("differential", "performance")
             if isinstance(entry.get(name), Mapping) and "not_applicable" in entry[name]]
    if not kinds:
        return []
    unmet = []
    if len(kinds) != 2:
        unmet.append(f"{key}: not_applicable must cover both differential and performance")
    for name in kinds:
        if not str(entry[name]["not_applicable"]).strip():
            unmet.append(f"{key}: {name} not_applicable needs a reason")
    rows = {(row["upstream"] if kind == "unit" else f"{row['upstream']}:{row['name']}"): row
            for kind in ("unit", "item") for row in port_map.get(kind, [])}
    if rows.get(key, {}).get("difference_kind") != "algorithmic":
        unmet.append(f"{key}: not_applicable is admitted only for an algorithmic row")
    defect = entry.get("c_defect")
    if not isinstance(defect, Mapping):
        return unmet + [f"{key}: not_applicable needs a c_defect naming the pinned C lines and its known difference"]
    lines = defect.get("source_lines")
    if not isinstance(lines, list) or not lines or not all(isinstance(line, str) and C_DEFECT_LINE.match(line)
                                                           for line in lines):
        unmet.append(f"{key}: c_defect.source_lines must name pinned C path:line[-line] entries")
    identifier = defect.get("known_difference")
    register = {item["id"]: item for item in source_convergence.known_difference_entries(register_text) if item["id"]}
    record = register.get(identifier)
    if record is None or (record["status"] or "").strip("*`") != "accepted":
        unmet.append(f"{key}: c_defect.known_difference {identifier!r} is not an accepted known-differences entry")
    elif key not in [ref for line in record["carriers"] for ref in line] and identifier not in str(
            rows.get(key, {}).get("intentional_difference", "")):
        unmet.append(f"{key}: known difference {identifier} is not carried by this row")
    return unmet


def validate_manifest(manifest: Mapping[str, Any], port_map: Mapping[str, Any],
                      register_text: str | None = None) -> dict[str, Any]:
    if manifest.get("schema") != SCHEMA or manifest.get("format") != 1:
        raise EvidenceError("divergence evidence manifest schema changed")
    rows = manifest.get("rows")
    if not isinstance(rows, Mapping):
        raise EvidenceError("divergence evidence manifest lacks rows")
    expected = algorithmic_rows(port_map)
    if sorted(rows) != expected:
        missing = sorted(set(expected) - set(rows))
        extra = sorted(set(rows) - set(expected))
        raise EvidenceError(f"divergence evidence rows differ from the algorithmic port-map rows: "
                            f"missing {missing}, not algorithmic {extra}")
    for key, entry in rows.items():
        if not isinstance(entry, Mapping):
            raise EvidenceError(f"{key} evidence entry is not an object")
        if "owner" in entry:
            if set(entry) != {"owner", "disposition"} or not all(isinstance(entry[k], str) and entry[k] for k in entry):
                raise EvidenceError(f"{key} owned entry must name only its owner and disposition")
            continue
        differential, performance = entry.get("differential"), entry.get("performance")
        if set(entry) - {"c_defect"} != {"differential", "performance"}:
            raise EvidenceError(f"{key} must name differential and performance evidence, or an owner")
        if not isinstance(differential, Mapping) or not (
            (set(differential) == {"command", "scope"} and isinstance(differential["command"], list)
             and len(differential["command"]) >= 2 and differential["command"][0] == "python3"
             and (ROOT / differential["command"][1]).is_file())
            or (set(differential) == {"not_applicable"} and isinstance(differential["not_applicable"], str))
        ):
            raise EvidenceError(f"{key} differential must be a runnable python3 command with a scope, or not_applicable")
        kinds = set(performance) - {"scope"} if isinstance(performance, Mapping) else set()
        if len(kinds) != 1 or not kinds <= {"integrated_rows", "engine_rows", "not_applicable", "blocked"}:
            raise EvidenceError(f"{key} performance must name exactly one of integrated_rows, engine_rows, "
                                "not_applicable or blocked")
        if "c_defect" in entry and "not_applicable" not in entry["differential"]:
            raise EvidenceError(f"{key} c_defect belongs only to a not_applicable entry")
        text = KNOWN_DIFFERENCES.read_text(encoding="utf-8") if register_text is None else register_text
        reasons = not_applicable_unmet(key, entry, port_map, text)
        if reasons:
            raise EvidenceError("; ".join(reasons))
    return {"rows": expected}


def accepted_not_applicable(manifest: Mapping[str, Any]) -> set[str]:
    """Rows whose validated evidence entry is not_applicable in both kinds."""

    return {key for key, entry in manifest["rows"].items()
            if "not_applicable" in (entry.get("differential") or {}) and "not_applicable" in (entry.get("performance") or {})}


def run_command(command: Sequence[str]) -> dict[str, Any]:
    import subprocess

    completed = subprocess.run(list(command), cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, check=False)
    return {"command": list(command), "status": completed.returncode, "tail": completed.stdout[-2000:]}


def evaluate(
    manifest: Mapping[str, Any], *, run: Callable[[Sequence[str]], Mapping[str, Any]] = run_command,
    integrated_rows: set[str] = frozenset(), engine_rows: set[str] = frozenset(),
) -> list[dict[str, Any]]:
    """Name every incomplete row; the two sets are rows some qualified report measured."""

    executed: dict[tuple[str, ...], Mapping[str, Any]] = {}
    results = []
    for key, entry in sorted(manifest["rows"].items()):
        if "owner" in entry:
            results.append({"row": key, "met": False,
                            "detail": [f"owned by {entry['owner']}: {entry['disposition']}"]})
            continue
        unmet: list[str] = []
        differential = entry["differential"]
        if "command" in differential:
            command = tuple(differential["command"])
            if command not in executed:
                executed[command] = run(command)
            if executed[command]["status"] != 0:
                unmet.append(f"differential {' '.join(command)} failed ({executed[command]['status']})")
        performance = entry["performance"]
        if "blocked" in performance:
            unmet.append(f"performance blocked: {performance['blocked']}")
        for group, available in (("integrated_rows", integrated_rows), ("engine_rows", engine_rows)):
            missing = [row for row in performance.get(group, []) if row not in available]
            if missing:
                unmet.append(f"performance: no qualified {group.split('_')[0]} report measures {missing}")
        results.append({"row": key, "met": not unmet, "detail": unmet or ["differential and performance evidence present"]})
    return results


def load() -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    with PORT_MAP.open("rb") as stream:
        port_map = tomllib.load(stream)
    validate_manifest(manifest, port_map)
    return manifest, port_map


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="validate the manifest against the port map only")
    arguments = parser.parse_args(argv)
    manifest, _ = load()
    if arguments.check:
        print(f"divergence evidence manifest covers {len(manifest['rows'])} algorithmic port-map rows")
        return 0
    sys.path.insert(0, str(ROOT / "compat/allocator"))
    import perf_engine_x86_64 as engine
    import perf_integrated_x86_64 as integrated
    import x86_64_m9_gate as gate

    integrated_rows: set[str] = set()
    for path in gate.discover_integrated():
        inspected = integrated.inspect_integrated_report(ROOT, path)
        if not inspected["unmet"]:
            integrated_rows.update(inspected["metrics"])
    engine_rows: set[str] = set()
    if any(not engine.inspect_full_report(ROOT, path)["unmet"] for path in gate.discover_reports()):
        timed, memory = engine.selected_rows(engine.load_manifest(), engine.QUALIFIED_ROW_SET)
        engine_rows = {row["name"] for row in (*timed, *memory)}
    results = evaluate(manifest, integrated_rows=integrated_rows, engine_rows=engine_rows)
    for result in results:
        print(f"{result['row']}: {'met' if result['met'] else 'unmet'}")
        for item in result["detail"]:
            print(f"  - {item}")
    return 0 if all(result["met"] for result in results) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except EvidenceError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
