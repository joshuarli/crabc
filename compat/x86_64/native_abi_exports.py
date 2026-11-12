#!/usr/bin/env python3
"""Compare a native x86 ABI inventory with the reviewed export delta."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

import native_abi_inventory as inventory


SCHEMA = "crabc.x86_64-native-abi-exports/v1"
TARGET = inventory.TARGET
TRACKED_PATH = ROOT / "compat/x86_64/native-abi-exports.json"
DYNAMIC_KEYS = ("name", "version", "version_default", "type", "binding", "visibility")
DATA_TYPES = frozenset({"OBJECT", "TLS"})
RUST_V0_PREFIX = "_R"
DYNAMIC_CATEGORIES = (
    "extra", "missing", "compatibility_differences", "data_size_differences", "version_differences",
)
STATIC_CATEGORIES = ("extra", "missing", "class_differences")
STATIC_ENTRY_KEYS = frozenset({"name", "nm_type", "count"})
CLASS_DIFFERENCE_KEYS = frozenset({"name", "reference", "candidate"})


class ExportsError(RuntimeError):
    """The inventory report or the reviewed delta is malformed."""


def require(condition: bool, message: str) -> None:
    if not condition: raise ExportsError(message)


def _key(value: object) -> str:
    return json.dumps(value, sort_keys=True)


def _sort_key(entry: Mapping[str, object]) -> tuple[object, ...]:
    return (
        entry["name"], "" if entry["version"] is None else entry["version"],
        entry["version_default"], entry["type"], entry["binding"], entry["visibility"],
        entry.get("size", ""),
    )


def _dynamic_entry(row: object, description: str, *, from_report: bool) -> dict[str, object]:
    if from_report:
        row = inventory.require_exact_keys(row, set(inventory.DYNAMIC_COLUMNS), description)
    else:
        require(isinstance(row, dict), f"{description} entries must be objects")
        row = inventory.require_exact_keys(
            row, set(DYNAMIC_KEYS) | ({"size"} if row.get("type") in DATA_TYPES else set()), description)
    entry = {key: row[key] for key in DYNAMIC_KEYS}
    require(isinstance(entry["name"], str) and entry["name"], f"{description} name is malformed")
    if entry["type"] in DATA_TYPES:
        require(isinstance(row["size"], str) and row["size"], f"{description} data size is malformed")
        entry["size"] = row["size"]
    return entry


def _static_names(rows: object, description: str, *, from_report: bool) -> list[str]:
    require(isinstance(rows, list), f"{description} must be a list")
    if from_report:
        names = []
        for row in rows:
            row = inventory.require_exact_keys(row, set(STATIC_ENTRY_KEYS), description)
            require(isinstance(row["name"], str) and row["name"], f"{description} name is malformed")
            names.append(row["name"])
        rows = names
    require(all(isinstance(name, str) and name for name in rows), f"{description} entries are malformed")
    return sorted({name for name in rows if not name.startswith(RUST_V0_PREFIX)})


def _objects(value: object, description: str, *, keys: frozenset[str] | None = None) -> list[dict[str, Any]]:
    require(isinstance(value, list) and all(isinstance(item, dict) for item in value), f"{description} must be a list of objects")
    return [dict(inventory.require_exact_keys(item, set(keys), description)) if keys else dict(item) for item in value]


def _categories(dynamic: object, static: object, description: str, *, from_report: bool) -> dict[str, Any]:
    dynamic = inventory.require_exact_keys(
        dynamic, set(DYNAMIC_CATEGORIES) | ({"measurement_differences"} if from_report else set()), f"{description} shared dynamic")
    static = inventory.require_exact_keys(static, set(STATIC_CATEGORIES), f"{description} static archive")
    shared = {}
    for category in DYNAMIC_CATEGORIES:
        if category in ("extra", "missing"):
            shared[category] = sorted(
                (_dynamic_entry(row, f"{description} {category}", from_report=from_report)
                 for row in dynamic[category]), key=_sort_key)
        else:
            shared[category] = _objects(dynamic[category], f"{description} {category}")
    archive = {}
    for category in STATIC_CATEGORIES:
        if category in ("extra", "missing"):
            archive[category] = _static_names(static[category], f"{description} {category}", from_report=from_report)
        else:
            archive[category] = _objects(static[category], f"{description} {category}", keys=CLASS_DIFFERENCE_KEYS)
    return {"shared_dynamic": shared, "static_archive": archive}


def load_report(path: Path) -> Mapping[str, Any]:
    try:
        return inventory.read_json(path, "native ABI inventory report")
    except inventory.InventoryError as error:
        raise ExportsError(f"native ABI inventory report is invalid: {error}") from error


def project(report: object) -> dict[str, Any]:
    require(isinstance(report, dict), "native ABI inventory report must be an object")
    require(report.get("schema") == inventory.SCHEMA and report.get("target") == TARGET, "native ABI inventory report contract drifted")
    triage = inventory.require_exact_keys(report.get("triage"), {"shared_dynamic", "static_archive", "disposition"}, "native ABI inventory triage")
    return _categories(triage["shared_dynamic"], triage["static_archive"], "report", from_report=True)


def load_tracked(path: Path | None = None) -> dict[str, Any]:
    path = TRACKED_PATH if path is None else path
    try:
        value = inventory.read_json(path, "reviewed native x86 export delta")
    except inventory.InventoryError as error:
        raise ExportsError(f"reviewed native x86 export delta is invalid: {error}") from error
    value = inventory.require_exact_keys(value, {"schema", "target", "shared_dynamic", "static_archive"}, "reviewed native x86 export delta")
    require(value["schema"] == SCHEMA and value["target"] == TARGET, "reviewed native x86 export delta contract drifted")
    return _categories(value["shared_dynamic"], value["static_archive"], "reviewed delta", from_report=False)


def differences(report_path: Path, *, tracked_path: Path | None = None) -> dict[str, dict[str, list[Any]]]:
    tracked = load_tracked(tracked_path)
    current = project(load_report(report_path))
    changes = {}
    for group, categories in (("shared_dynamic", DYNAMIC_CATEGORIES), ("static_archive", STATIC_CATEGORIES)):
        for category in categories:
            left = {_key(item): item for item in tracked[group][category]}
            right = {_key(item): item for item in current[group][category]}
            change = {
                "added": sorted((right[key] for key in right.keys() - left.keys()), key=_key),
                "removed": sorted((left[key] for key in left.keys() - right.keys()), key=_key),
            }
            if change["added"] or change["removed"]:
                changes[f"{group}.{category}"] = change
    return changes


def require_matching(report_path: Path, *, tracked_path: Path | None = None) -> None:
    changes = differences(report_path, tracked_path=tracked_path)
    if changes:
        raise ExportsError("native x86 export delta differs: " + ", ".join(sorted(changes)))


def check(report_path: Path, *, tracked_path: Path | None = None, stream: Any = None) -> bool:
    stream = sys.stdout if stream is None else stream
    changes = differences(report_path, tracked_path=tracked_path)
    if not changes:
        stream.write("native x86 export delta: match\n")
        return True
    for category, change in changes.items():
        stream.write(f"{category}: +{len(change['added'])} -{len(change['removed'])}\n")
        for sign, items in (("+", change["added"]), ("-", change["removed"])):
            for item in items:
                stream.write(f"  {sign} " + _key(item) + "\n")
    return False


def update(report_path: Path, *, tracked_path: Path | None = None) -> Path:
    tracked_path = TRACKED_PATH if tracked_path is None else tracked_path
    tracked = {"schema": SCHEMA, "target": TARGET, **project(load_report(report_path))}
    try:
        tracked_path.write_bytes((json.dumps(tracked, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    except OSError as error:
        raise ExportsError(f"cannot write reviewed native x86 export delta: {tracked_path}") from error
    return tracked_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("check", "update"):
        commands.add_parser(name).add_argument("report", type=Path)
    arguments = parser.parse_args(argv)
    try:
        if arguments.action == "check":
            return 0 if check(arguments.report) else 1
        print(update(arguments.report))
        return 0
    except (ExportsError, OSError) as error:
        print(f"native ABI exports error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
