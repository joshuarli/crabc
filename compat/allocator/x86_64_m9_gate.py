#!/usr/bin/env python3
"""Fail-closed native Linux/x86-64 gate for allocator Milestone 9.

M9 is "full equivalent C/Rust performance/memory matrix, codegen audit,
source-faithful convergence and at least three agreeing qualified full
reports; correctness stays green" (plan.md Milestones). This gate is
read-only: it measures nothing and names every unmet condition.

* ``m9.matrix``: the engine matrix manifest validates, its critical roster
  names timed matrix rows, and at least one full report's raw samples carry
  every promotion-table metric (throughput, p99, peak RSS, peak PSS) of
  every matrix row.
* ``m9.qualified-reports``: at least three engine reports that
  ``perf_engine_x86_64.validate_qualified_full_report`` accepts. Without
  ``--report`` every ``--full`` report under the engine report directory is
  read; each refused report is named with the reader's reasons.
* ``m9.agreement``: the accepted reports share one source/configuration/host
  identity and one critical roster.
* ``m9.codegen-audit``: one complete ``allocator-codegen-audit`` report from a
  clean checkout whose source seal matches this checkout, with no Rust-only
  structural cost (``rust_excess``) in any traced region.
* ``m9.source-convergence`` and ``m9.integrated-products``: declared missing.
  No convergence reader exists, and no existing M8 or native-shadow receipt
  measures integrated-product C/Rust performance or memory to read.
* ``m9.correctness``: the retained M4, M5, M6 and M7 gate reports passed.
  They record no source identity, so each must also be no older than the
  newest accepted qualified report. M8 has no gate here and is named.

The ``performance.release`` gate applies the promotion thresholds to the same
reader's metrics; M9 decides qualification and agreement only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import perf_engine_x86_64 as engine
import run as harness


CONDITION_IDS = (
    "m9.matrix",
    "m9.qualified-reports",
    "m9.agreement",
    "m9.codegen-audit",
    "m9.source-convergence",
    "m9.integrated-products",
    "m9.correctness",
)
MINIMUM_REPORTS = 3
ENGINE_REPORTS = engine.REPORT_ROOT
CODEGEN_REPORTS = engine.REPORT_ROOT.parent / "codegen-audit"
CORRECTNESS_GATES = ("m4", "m5", "m6", "m7")
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m9-gate"
DECLARED_MISSING = {
    "m9.source-convergence": [
        "plan.md M9 requires source-faithful convergence of the Rust port; no convergence reader exists in "
        "compat/allocator, so this gate cannot establish it"
    ],
    "m9.integrated-products": [
        "the engine matrix measures one opaque engine boundary (scope.fully_integrated_products is false); "
        "no fully-integrated-product C/Rust allocator performance and memory comparison exists: the M8 and "
        "native-shadow receipts (compat/x86_64/run_dynamic_native_allocator.py, "
        "compat/x86_64/native_c_allocator_boundary.py, compat/allocator/native_churn_rss_smoke.py) compare "
        "ownership, lifecycle and liveness, not throughput, tail latency or peak memory"
    ],
}

Reader = Callable[[Path, Path], Mapping[str, Any]]


def _condition(identifier: str, unmet: Sequence[str], detail: str) -> dict[str, Any]:
    return {"id": identifier, "met": not unmet, "detail": detail if not unmet else list(unmet)}


def matrix_condition(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Met when one full report's raw samples carry every metric of every matrix row."""

    try:
        manifest = engine.load_manifest()
    except engine.HarnessError as error:
        return _condition("m9.matrix", [str(error)], "")
    timed, memory = engine.selected_rows(manifest, engine.QUALIFIED_ROW_SET)
    covered = [record["path"] for record in records if record.get("coverage") == {}]
    unmet = []
    if not covered:
        unmet.append("no full report carries throughput, tail, peak RSS and peak PSS for every matrix row")
        for record in records:
            coverage = record.get("coverage")
            if coverage:
                unmet.append(f"{record['path']}: " + "; ".join(
                    f"{name} lacks {', '.join(lacks)}" for name, lacks in sorted(coverage.items())))
    return _condition("m9.matrix", unmet, f"{len(timed)} timed and {len(memory)} memory rows, "
                      f"{len(engine.critical_rows(manifest))} critical, all measured in {covered[:1]}")


def discover_reports(directory: Path = ENGINE_REPORTS) -> list[Path]:
    """Every engine report that claims full mode; smoke runs claim nothing."""

    found = []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            if json.loads(path.read_text(encoding="utf-8")).get("mode") == engine.QUALIFIED_MODE:
                found.append(path)
        except (OSError, json.JSONDecodeError, AttributeError):
            found.append(path)
    return found


def read_reports(paths: Sequence[Path], inspect: Callable[[Path, Path], Mapping[str, Any]]) -> list[dict[str, Any]]:
    records = []
    for path in paths:
        try:
            inspected = dict(inspect(harness.ROOT, path))
        except Exception as error:  # noqa: BLE001 - a reader refusal is the unmet detail
            inspected = {"unmet": [f"{type(error).__name__}: {error}"], "identity": None, "metrics": None}
        records.append({"path": harness.relative(Path(path)), **inspected})
    return records


def report_conditions(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    accepted = [record for record in records if not record["unmet"]]
    unmet = [f"{record['path']}: " + "; ".join(record["unmet"]) for record in records if record["unmet"]]
    if len(accepted) < MINIMUM_REPORTS:
        unmet.insert(0, f"{len(accepted)} qualified full report(s) of {len(records)} read; "
                        f"M9 requires at least {MINIMUM_REPORTS}")
    qualified = _condition("m9.qualified-reports", unmet, f"{len(accepted)} qualified full reports")
    return [qualified, agreement_condition(accepted)]


def agreement_condition(accepted: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Accepted reports must share one identity and one critical roster."""

    unmet = []
    if len(accepted) < MINIMUM_REPORTS:
        unmet.append(f"agreement needs {MINIMUM_REPORTS} qualified reports; {len(accepted)} accepted")
    if accepted:
        first = accepted[0]
        for record in accepted[1:]:
            for part in ("source", "configuration", "host"):
                if (record["identity"] or {}).get(part) != (first["identity"] or {}).get(part):
                    unmet.append(f"{record['path']} {part} identity differs from {first['path']}")
            if record.get("critical_rows") != first.get("critical_rows"):
                unmet.append(f"{record['path']} critical roster differs from {first['path']}")
        for record in accepted:
            metrics = record.get("metrics") or {}
            rosters = {
                frozenset(metrics.get("throughput", {}).get("critical_lower_95", {})),
                frozenset(metrics.get("tail_latency", {}).get("critical_p99_upper_95", {})),
                frozenset(metrics.get("memory", {}).get("critical_peak_upper", {})),
            }
            if rosters != {frozenset(record.get("critical_rows") or ())}:
                unmet.append(f"{record['path']} metrics do not cover exactly its critical roster")
    return _condition("m9.agreement", unmet, f"{len(accepted)} reports share one identity and critical roster")


def newest_codegen_report(directory: Path = CODEGEN_REPORTS) -> Path | None:
    reports = sorted(directory.glob("*.json"), key=lambda path: path.stat().st_mtime) if directory.is_dir() else []
    return reports[-1] if reports else None


def codegen_unmet(report: Mapping[str, Any], scenarios: Sequence[str]) -> list[str]:
    unmet = []
    if report.get("status") != "ok":
        unmet.append(f"codegen audit status is {report.get('status')}")
    traced = report.get("scenarios", {})
    missing = sorted(set(scenarios) - set(traced))
    if missing:
        unmet.append(f"codegen audit omits scenarios {missing}")
    provenance = report.get("provenance", {})
    if provenance.get("git", {}).get("clean") is not True:
        unmet.append("codegen audit was not taken from a clean Git tree")
    unmet.extend(f"codegen audit {item}" for item in engine.source_seal_unmet(provenance.get("inputs", {})))
    for name, scenario in sorted(traced.items()):
        for region, comparison in sorted(scenario.get("comparison", {}).items()):
            for excess in comparison.get("rust_excess", []):
                unmet.append(f"codegen {name}/{region}: {excess}")
    return unmet


def codegen_condition(path: Path | None) -> dict[str, Any]:
    if path is None:
        return _condition("m9.codegen-audit", ["no allocator-codegen-audit report exists"], "")
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
        import codegen_audit_x86_64 as codegen

        unmet = codegen_unmet(report, [scenario.name for scenario in codegen.SCENARIOS])
    except Exception as error:  # noqa: BLE001
        unmet = [f"{type(error).__name__}: {error}"]
    return _condition("m9.codegen-audit", [f"{harness.relative(Path(path))}: {item}" for item in unmet],
                      f"{harness.relative(Path(path))} has no Rust-only structural cost")


def correctness_condition(accepted_paths: Sequence[Path], gate_root: Path = harness.ARTIFACT_ROOT / "x86_64") -> dict[str, Any]:
    unmet = ["allocator M8 has no gate in this launcher"]
    newest = max((Path(path).stat().st_mtime for path in accepted_paths), default=None)
    for gate in CORRECTNESS_GATES:
        path = gate_root / f"{gate}-gate/report.json"
        if not path.is_file():
            unmet.append(f"{gate.upper()} gate has no retained report ({harness.relative(path)})")
            continue
        try:
            status = json.loads(path.read_text(encoding="utf-8")).get("overall_status")
        except (OSError, json.JSONDecodeError, AttributeError) as error:
            unmet.append(f"{gate.upper()} gate report is unreadable: {error}")
            continue
        if status != "passed":
            unmet.append(f"{gate.upper()} gate report is {status}")
        elif newest is not None and path.stat().st_mtime < newest:
            unmet.append(f"{gate.upper()} gate report predates the newest qualified report")
    return _condition("m9.correctness", unmet, "M4-M8 correctness gates passed after the qualified reports")


def evaluate(
    report_paths: Sequence[Path], codegen_report: Path | None,
    inspect: Callable[[Path, Path], Mapping[str, Any]] = engine.inspect_full_report,
    gate_root: Path = harness.ARTIFACT_ROOT / "x86_64",
) -> dict[str, Any]:
    records = read_reports(report_paths, inspect)
    accepted = [Path(path) for path, record in zip(report_paths, records) if not record["unmet"]]
    conditions = [
        matrix_condition(records),
        *report_conditions(records),
        codegen_condition(codegen_report),
        *(_condition(identifier, detail, "") for identifier, detail in DECLARED_MISSING.items()),
        correctness_condition(accepted, gate_root),
    ]
    assert [row["id"] for row in conditions] == list(CONDITION_IDS)
    unmet = [row["id"] for row in conditions if not row["met"]]
    return {
        "schema": "crabc-mimalloc-x86_64-m9-gate/v1",
        "reports": records,
        "codegen_report": harness.relative(Path(codegen_report)) if codegen_report else None,
        "conditions": conditions,
        "unmet": unmet,
        "overall_status": "passed" if not unmet else "unmet",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="validate the matrix manifest and critical roster without reading reports")
    parser.add_argument("--report", type=Path, action="append", default=None,
                        help="engine report to read (default: every --full report under the engine report directory)")
    parser.add_argument("--codegen-report", type=Path, default=None,
                        help="codegen audit report (default: the newest one)")
    arguments = parser.parse_args(argv)
    if arguments.check:
        manifest = engine.load_manifest()
        timed, memory = engine.selected_rows(manifest, engine.QUALIFIED_ROW_SET)
        print(f"M9 gate valid: {len(timed)} timed and {len(memory)} memory matrix rows, "
              f"{len(engine.critical_rows(manifest))} critical rows, {len(CONDITION_IDS)} conditions")
        return 0
    reports = arguments.report if arguments.report is not None else discover_reports()
    codegen_report = arguments.codegen_report or newest_codegen_report()
    result = evaluate(reports, codegen_report)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    harness.write_json(ARTIFACTS / "report.json", result)
    for row in result["conditions"]:
        print(f"{row['id']}: {'met' if row['met'] else 'unmet'}")
        if not row["met"]:
            for item in row["detail"]:
                print(f"  - {item if len(item) <= 600 else item[:600] + ' ...'}")
    if result["unmet"]:
        print(f"M9 unmet: {len(result['unmet'])}/{len(CONDITION_IDS)} conditions; "
              f"report {harness.relative(ARTIFACTS / 'report.json')}", file=sys.stderr)
        return 1
    print("M9 passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (harness.HarnessError, engine.HarnessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
