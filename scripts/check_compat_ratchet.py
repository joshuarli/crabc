#!/usr/bin/env python3
"""Create and enforce the monotonic AArch64 public-dynamic-symbol ratchet.

The baseline is a compatibility contract, not a claim that every current
export is correct. Symbols missing at the baseline may be added later only
with their musl kind, binding, and visibility already correct. Existing ABI
matches may not regress, and no new unexpected public exports are permitted.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_REPORT_DIR = ROOT_DIR / "compat/reports/symbols"
DEFAULT_BASELINE = ROOT_DIR / "compat/ratchet/aarch64-dynamic.json"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("snapshot", "check"))
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    return parser.parse_args()


def read_manifest(path: Path) -> dict[str, dict[str, str]]:
    if not path.is_file():
        raise RuntimeError(f"symbol manifest not found: {path}")
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream, delimiter="\t")
        records = {
            row[0]: {
                "type": row[1],
                "binding": row[2],
                "visibility": row[3],
                "size": row[4],
            }
            for row in reader
            if row
        }
    if len(records) == 0:
        raise RuntimeError(f"symbol manifest was empty: {path}")
    return records


def current_state(report_dir: Path) -> dict[str, object]:
    expected = read_manifest(report_dir / "musl-1.2.6-aarch64.dynamic.tsv")
    candidate = read_manifest(report_dir / "crabc-aarch64.dynamic.tsv")
    expected_abi = {
        name: {key: record[key] for key in ("type", "binding", "visibility")}
        for name, record in expected.items()
    }
    expected_names = set(expected)
    candidate_names = set(candidate)
    missing = sorted(expected_names - candidate_names)
    unexpected = sorted(candidate_names - expected_names)
    matched: dict[str, dict[str, str]] = {}
    mismatched: dict[str, dict[str, dict[str, str]]] = {}
    for name in sorted(expected_names & candidate_names):
        symbol_expected_abi = expected_abi[name]
        candidate_abi = {
            key: candidate[name][key] for key in ("type", "binding", "visibility")
        }
        if symbol_expected_abi == candidate_abi:
            matched[name] = symbol_expected_abi
        else:
            mismatched[name] = {"expected": symbol_expected_abi, "actual": candidate_abi}
    return {
        "expected": expected_abi,
        "candidate": candidate,
        "missing": missing,
        "unexpected": unexpected,
        "matched": matched,
        "mismatched": mismatched,
    }


def snapshot(state: dict[str, object], baseline_path: Path) -> None:
    baseline = {
        "format": 1,
        "target": "aarch64-unknown-linux-musl",
        "reference": "musl-1.2.6",
        "expected": state["expected"],
        "missing": state["missing"],
        "unexpected": state["unexpected"],
        "matched": state["matched"],
        "mismatched": state["mismatched"],
    }
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(baseline_path)


def check(state: dict[str, object], baseline_path: Path, report_dir: Path) -> int:
    if not baseline_path.is_file():
        raise RuntimeError(f"ratchet baseline not found: {baseline_path}")
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    if baseline.get("format") != 1:
        raise RuntimeError(f"unsupported ratchet baseline: {baseline_path}")

    current_expected = state["expected"]
    if current_expected != baseline["expected"]:
        raise RuntimeError(
            "the musl oracle manifest changed; regenerate and review the baseline explicitly"
        )

    baseline_missing = set(baseline["missing"])
    current_missing = set(state["missing"])
    baseline_unexpected = set(baseline["unexpected"])
    current_unexpected = set(state["unexpected"])
    baseline_mismatched = set(baseline["mismatched"])
    current_mismatched = set(state["mismatched"])
    current_matched = state["matched"]

    violations: dict[str, list[str]] = {
        "new_missing": sorted(current_missing - baseline_missing),
        "new_unexpected": sorted(current_unexpected - baseline_unexpected),
        "new_metadata_mismatches": sorted(current_mismatched - baseline_mismatched),
        "regressed_matches": sorted(
            name
            for name, expected_abi in baseline["matched"].items()
            if current_matched.get(name) != expected_abi
        ),
    }
    report = {
        "baseline": str(baseline_path),
        "current_missing": len(current_missing),
        "current_unexpected": len(current_unexpected),
        "current_metadata_mismatches": len(current_mismatched),
        "violations": violations,
    }
    ratchet_report = report_dir.parent / "ratchet.json"
    ratchet_report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(ratchet_report)
    for category, names in violations.items():
        if names:
            print(f"{category}: {', '.join(names)}")
    return int(any(violations.values()))


def main() -> int:
    arguments = parse_arguments()
    state = current_state(arguments.report_dir)
    if arguments.action == "snapshot":
        snapshot(state, arguments.baseline)
        return 0
    return check(state, arguments.baseline, arguments.report_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"ERROR: {error}")
        raise SystemExit(2)
