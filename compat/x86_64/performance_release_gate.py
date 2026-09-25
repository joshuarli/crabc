#!/usr/bin/env python3
"""Evaluate the x86 ``performance.release`` gate from retained receipts only.

This gate never measures. ``evaluate`` reads three kinds of existing
performance evidence through each owner's own reader, applies the release
thresholds of ``plan.md`` and writes ``NEW_DIR/receipt.json`` naming every
unmet condition; ``validate_receipt`` reruns that evaluation from the same
inputs, so a replaced input, a changed owner reader or a later source change
cannot pass. The ``performance-release`` publication of
``qualification_gates.py`` selects one receipt. The inputs are:

* the runtime C scorecard: a three-attempt ``perf-c collect`` report replayed
  by ``compat/perf/x86_64_evidence.validate_collector_report`` (the
  ``perf-c check`` reader). Its release decision must be qualified with no
  blocker, and every row of every attempt is rechecked against the
  "Runtime performance and qualification" scorecard: CPU one-sided 95% upper
  bound <= 0.90, PSS and ``memory.peak`` ratios <= 0.90 against a nonzero
  reference, and marked-region and whole-process syscalls <= 2R (zero when
  R is zero);
* the native Rust-facade companion: one ``perf-native --mode full`` report
  replayed by ``compat/perf/native/x86_64_runner.validate_report``. It is a
  supporting comparison with no threshold of its own, so it must only be
  complete full-mode evidence;
* at least three allocator M9 qualified full reports. ``compat/allocator``
  owns their replay through ``perf_engine_x86_64.validate_qualified_full_report
  (root, path)``, which returns ``{"identity": ..., "metrics": ...}``; this gate
  applies the allocator promotion table to those metrics: suite
  geometric-mean throughput lower 95% bound >= 0.95, every critical row's
  throughput lower bound >= 0.90, critical p99 upper bound <= 1.10,
  geometric-mean peak RSS and PSS upper ratio <= 1.05 and every critical
  row's <= 1.10, one nonempty critical roster shared by all three metrics,
  and agreement: every report meets them with one identical
  source/configuration/host identity. No reviewed exception or explanation
  is encoded here; such a decision belongs to the user and the plan.

Every receipt must also carry an ``uncontended_host`` record,
``{"status": "uncontended", "evidence": {...nonempty raw observations...}}``,
written by its producer on the measuring host. Its absence is a named unmet
condition; this gate does not decide what makes a host uncontended.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
GATE = "performance.release"
SCHEMA = "crabc.x86_64-performance-release-gate/v1"
RECEIPT_NAME = "receipt.json"

# Runtime C scorecard, plan.md "Runtime performance and qualification".
RUNTIME_CPU_UPPER_MAX = 0.90
RUNTIME_MEMORY_RATIO_MAX = 0.90
RUNTIME_SYSCALL_FACTOR = 2
# Allocator promotion table, plan.md "Allocator verification and performance" (M9).
ALLOCATOR_SUITE_THROUGHPUT_LOWER_MIN = 0.95
ALLOCATOR_CRITICAL_THROUGHPUT_LOWER_MIN = 0.90
ALLOCATOR_CRITICAL_P99_UPPER_MAX = 1.10
ALLOCATOR_MEMORY_GEOMEAN_UPPER_MAX = 1.05
ALLOCATOR_CRITICAL_MEMORY_UPPER_MAX = 1.10
ALLOCATOR_MINIMUM_REPORTS = 3
ALLOCATOR_READER = "validate_qualified_full_report"


class GateInputError(RuntimeError):
    """A command-line input or retained receipt is malformed."""


def _condition(identifier: str, unmet: Sequence[str], met_detail: str) -> dict[str, Any]:
    return {"id": identifier, "met": not unmet, "detail": met_detail if not unmet else list(unmet)}


def _module(directory: Path, name: str) -> Any:
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))
    return __import__(name)


def _checkout_path(value: str | Path) -> str:
    """Return one checkout-relative spelling, without traversal or links."""
    path = Path(os.path.abspath(ROOT / value)) if not Path(value).is_absolute() else Path(value)
    try:
        relative = path.relative_to(ROOT)
    except ValueError as error:
        raise GateInputError(f"performance input must be below this checkout: {value}") from error
    current = ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise GateInputError(f"performance input crosses a symlink: {value}")
    return relative.as_posix()


def _file_identity(relative: str) -> dict[str, Any]:
    path = ROOT / relative
    digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    return {"path": relative, "sha256": digest}


def _read_json(relative: str) -> Mapping[str, Any]:
    value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise GateInputError(f"{relative} is not a JSON object")
    return value


def _guard(identifier: str, read: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Every reader rejection is one named unmet condition, never a crash."""
    try:
        return read()
    except Exception as error:  # noqa: BLE001 - an owner reader's refusal is the unmet detail
        return {"id": identifier, "met": False, "detail": [f"{type(error).__name__}: {error}"]}


def uncontended_host_unmet(record: Mapping[str, Any], label: str) -> list[str]:
    host = record.get("uncontended_host")
    if not isinstance(host, Mapping):
        return [f"{label} has no uncontended_host record from its measuring host"]
    evidence = host.get("evidence")
    if host.get("status") != "uncontended" or not isinstance(evidence, Mapping) or not evidence:
        return [f"{label} uncontended_host record is not an uncontended status with raw evidence"]
    return []


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return float(value)


# ---------------------------------------------------------------------------
# Runtime C scorecard


def runtime_row_unmet(name: str, attempt: int, row: Mapping[str, Any]) -> list[str]:
    """Recheck one retained scorecard row against the plan's per-workload rules."""
    label = f"{name} attempt {attempt}"
    unmet: list[str] = []
    upper = _number(row.get("cpu", {}).get("one_sided_95_upper"))
    if upper is None or upper > RUNTIME_CPU_UPPER_MAX:
        unmet.append(f"{label}: CPU one-sided 95% upper bound {upper} > {RUNTIME_CPU_UPPER_MAX}")
    for metric in ("pss_kib", "memory_peak_bytes"):
        values = row.get(metric, {})
        reference, candidate = _number(values.get("reference")), _number(values.get("candidate"))
        if reference is None or candidate is None or reference <= 0:
            unmet.append(f"{label}: {metric} has no nonzero reference measurement")
        elif candidate / reference > RUNTIME_MEMORY_RATIO_MAX:
            unmet.append(f"{label}: {metric} ratio {candidate / reference:.4f} > {RUNTIME_MEMORY_RATIO_MAX}")
    for scope in ("marked_region", "whole_process"):
        counts = row.get("syscalls", {}).get(scope, {})
        reference, candidate = counts.get("reference"), counts.get("candidate")
        if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0
                   for value in (reference, candidate)):
            unmet.append(f"{label}: {scope} syscall totals are absent")
        elif candidate > RUNTIME_SYSCALL_FACTOR * reference:
            unmet.append(f"{label}: {scope} syscalls {candidate} > {RUNTIME_SYSCALL_FACTOR}R={RUNTIME_SYSCALL_FACTOR * reference}")
    for metric, gate in (("cpu", row.get("cpu", {}).get("gate")), ("pss", row.get("pss_kib", {}).get("gate")),
                         ("memory.peak", row.get("memory_peak_bytes", {}).get("gate")),
                         ("syscalls", row.get("syscalls", {}).get("gate"))):
        if gate != "pass":
            unmet.append(f"{label}: {metric} release gate is {gate}")
    return unmet


def runtime_c_conditions(collector: str) -> list[dict[str, Any]]:
    def read() -> dict[str, Any]:
        evidence = _module(ROOT / "compat" / "perf", "x86_64_evidence")
        checked = evidence.validate_collector_report(ROOT, ROOT / collector)
        unmet = [f"collector release blocker: {blocker}" for blocker in checked.blockers]
        if not checked.release_qualified and not unmet:
            unmet.append("collector release decision is not qualified")
        rows = checked.scorecard["rows"] if checked.scorecard else {}
        if not rows:
            unmet.append("collector scorecard has no rows")
        for name, row in rows.items():
            for index, attempt in enumerate(row["attempts"], start=1):
                unmet.extend(runtime_row_unmet(name, index, attempt))
        return _condition("runtime-c-scorecard", unmet, f"{len(rows)} rows pass in all three attempts")

    rows = [_guard("runtime-c-scorecard", read)]
    rows.append(_guard("runtime-c-uncontended-host", lambda: _condition(
        "runtime-c-uncontended-host", uncontended_host_unmet(_read_json(collector), "runtime C collector report"),
        "uncontended host recorded")))
    return rows


# ---------------------------------------------------------------------------
# Native Rust-facade companion


def native_facade_conditions(report: str, rustybench: str, rustix: str) -> list[dict[str, Any]]:
    def read() -> dict[str, Any]:
        runner = _module(ROOT / "compat" / "perf" / "native", "x86_64_runner")
        runner.validate_report(ROOT, ROOT / report, rustybench_source=ROOT / rustybench, rustix_source=ROOT / rustix)
        value = _read_json(report)
        unmet = []
        if value.get("mode") != "full" or value.get("status") != runner.MODE_STATUS["full"]:
            unmet.append(f"native facade report is {value.get('mode')}/{value.get('status')}, not full complete evidence")
        return _condition("native-facade-full", unmet, "complete full-mode Rust-facade comparison")

    rows = [_guard("native-facade-full", read)]
    rows.append(_guard("native-facade-uncontended-host", lambda: _condition(
        "native-facade-uncontended-host", uncontended_host_unmet(_read_json(report), "native facade report"),
        "uncontended host recorded")))
    return rows


# ---------------------------------------------------------------------------
# Allocator M9 qualified full reports


def _rows(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def allocator_metric_unmet(label: str, metrics: Mapping[str, Any]) -> list[str]:
    """Apply the allocator promotion table to one reader-validated report."""
    unmet: list[str] = []
    throughput = _rows(metrics.get("throughput"))
    tail = _rows(metrics.get("tail_latency"))
    memory = _rows(metrics.get("memory"))
    suite = _number(throughput.get("suite_geometric_mean_lower_95"))
    if suite is None or suite < ALLOCATOR_SUITE_THROUGHPUT_LOWER_MIN:
        unmet.append(f"{label}: suite geometric-mean throughput lower 95% bound {suite} < "
                     f"{ALLOCATOR_SUITE_THROUGHPUT_LOWER_MIN}")
    critical_throughput = _rows(throughput.get("critical_lower_95"))
    critical_tail = _rows(tail.get("critical_p99_upper_95"))
    critical_memory = _rows(memory.get("critical_peak_upper"))
    rosters = {frozenset(critical_throughput), frozenset(critical_tail), frozenset(critical_memory)}
    if len(rosters) != 1 or not critical_throughput:
        unmet.append(f"{label}: throughput, tail-latency and memory do not share one nonempty critical roster")
    for row, value in critical_throughput.items():
        bound = _number(value)
        if bound is None or bound < ALLOCATOR_CRITICAL_THROUGHPUT_LOWER_MIN:
            unmet.append(f"{label}: critical {row} throughput lower bound {bound} < "
                         f"{ALLOCATOR_CRITICAL_THROUGHPUT_LOWER_MIN}")
    for row, value in critical_tail.items():
        bound = _number(value)
        if bound is None or bound > ALLOCATOR_CRITICAL_P99_UPPER_MAX:
            unmet.append(f"{label}: critical {row} p99 upper bound {bound} > {ALLOCATOR_CRITICAL_P99_UPPER_MAX}")
    geomean = _rows(memory.get("geometric_mean_peak_upper"))
    for kind in ("rss", "pss"):
        bound = _number(geomean.get(kind))
        if bound is None or bound > ALLOCATOR_MEMORY_GEOMEAN_UPPER_MAX:
            unmet.append(f"{label}: geometric-mean peak {kind.upper()} upper ratio {bound} > "
                         f"{ALLOCATOR_MEMORY_GEOMEAN_UPPER_MAX}")
    for row, value in critical_memory.items():
        for kind in ("rss", "pss"):
            bound = _number(_rows(value).get(kind))
            if bound is None or bound > ALLOCATOR_CRITICAL_MEMORY_UPPER_MAX:
                unmet.append(f"{label}: critical {row} peak {kind.upper()} upper ratio {bound} > "
                             f"{ALLOCATOR_CRITICAL_MEMORY_UPPER_MAX}")
    return unmet


def allocator_conditions(reports: Sequence[str]) -> list[dict[str, Any]]:
    count_unmet = []
    if len(reports) < ALLOCATOR_MINIMUM_REPORTS:
        count_unmet.append(f"{len(reports)} allocator report(s); M9 requires at least {ALLOCATOR_MINIMUM_REPORTS}")
    if len(set(reports)) != len(reports):
        count_unmet.append("an allocator report is supplied more than once")
    identities: list[object] = []

    def read() -> dict[str, Any]:
        unmet = list(count_unmet)
        engine = _module(ROOT / "compat" / "allocator", "perf_engine_x86_64")
        reader = getattr(engine, ALLOCATOR_READER, None)
        if reader is None:
            unmet.append(f"compat/allocator has no qualified full-report reader "
                         f"(perf_engine_x86_64.{ALLOCATOR_READER}); no allocator report can qualify")
            return _condition("allocator-m9-reports", unmet, "")
        for report in reports:
            try:
                validated = reader(ROOT, ROOT / report)
            except Exception as error:  # noqa: BLE001 - the owner's refusal is the unmet detail
                unmet.append(f"{report}: {type(error).__name__}: {error}")
                continue
            identities.append(validated.get("identity"))
            unmet.extend(allocator_metric_unmet(report, _rows(validated.get("metrics"))))
        if len(identities) == len(reports) and (not identities[0] or any(item != identities[0] for item in identities)):
            unmet.append("allocator reports do not agree on one source/configuration/host identity")
        return _condition("allocator-m9-reports", unmet,
                          f"{len(reports)} agreeing qualified full reports meet the M9 promotion table")

    rows = [_guard("allocator-m9-reports", read)]

    def hosts() -> dict[str, Any]:
        unmet: list[str] = []
        for report in reports:
            try:
                unmet.extend(uncontended_host_unmet(_read_json(report), f"allocator report {report}"))
            except Exception as error:  # noqa: BLE001
                unmet.append(f"{report}: {type(error).__name__}: {error}")
        return _condition("allocator-m9-uncontended-host", unmet,
                          "uncontended host recorded in every allocator report")

    rows.append(hosts())
    return rows


# ---------------------------------------------------------------------------
# Receipt


def evaluate_inputs(inputs: Mapping[str, Any]) -> list[dict[str, Any]]:
    native = inputs["native_facade"]
    return [
        *runtime_c_conditions(inputs["runtime_c_collector"]["path"]),
        *native_facade_conditions(native["report"]["path"], native["rustybench_source"], native["rustix_source"]),
        *allocator_conditions([item["path"] for item in inputs["allocator_reports"]]),
    ]


def collect_inputs(arguments: argparse.Namespace) -> dict[str, Any]:
    return {
        "runtime_c_collector": _file_identity(_checkout_path(arguments.runtime_c_collector)),
        "native_facade": {
            "report": _file_identity(_checkout_path(arguments.native_facade_report)),
            "rustybench_source": _checkout_path(arguments.rustybench_source),
            "rustix_source": _checkout_path(arguments.rustix_source),
        },
        "allocator_reports": [_file_identity(_checkout_path(path)) for path in arguments.allocator_report],
    }


def build_receipt(inputs: Mapping[str, Any]) -> dict[str, Any]:
    conditions = evaluate_inputs(inputs)
    unmet = [row["id"] for row in conditions if row["met"] is not True]
    return {"schema": SCHEMA, "gate": GATE, "inputs": dict(inputs), "conditions": conditions,
            "unmet": unmet, "passed": not unmet}


def write_receipt(output: Path, receipt: Mapping[str, Any]) -> Path:
    relative = _checkout_path(output)
    path = ROOT / relative
    if not relative.startswith(".work/") or path.exists():
        raise GateInputError(f"performance-release output must be a fresh .work directory: {output}")
    path.mkdir()
    target = path / RECEIPT_NAME
    target.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def validate_receipt(root: Path, path: Path) -> dict[str, Any]:
    """Rerun the evaluation from the receipt's inputs; pass only when it still passes."""
    if Path(root).resolve() != ROOT:
        raise GateInputError("performance-release receipt must be read by this checkout")
    relative = _checkout_path(path)
    if Path(relative).name != RECEIPT_NAME or not relative.startswith(".work/"):
        raise GateInputError(f"performance-release receipt must be a .work {RECEIPT_NAME}")
    record = _read_json(relative)
    if set(record) != {"schema", "gate", "inputs", "conditions", "unmet", "passed"} or (
        record["schema"], record["gate"]) != (SCHEMA, GATE):
        raise GateInputError("performance-release receipt does not match its schema")
    inputs = record["inputs"]
    files = [inputs["runtime_c_collector"], inputs["native_facade"]["report"], *inputs["allocator_reports"]]
    changed = [item["path"] for item in files if _file_identity(_checkout_path(item["path"])) != item]
    if changed:
        raise GateInputError("performance-release inputs changed after evaluation: " + ", ".join(changed))
    fresh = build_receipt(inputs)
    # Details may spell host or container paths; the verdicts may not differ.
    def verdicts(value: Mapping[str, Any]) -> list[tuple[object, object]]:
        return [(row.get("id"), row.get("met")) for row in value["conditions"]]

    if verdicts(fresh) != verdicts(record) or (fresh["unmet"], fresh["passed"]) != (record["unmet"], record["passed"]):
        raise GateInputError("performance-release receipt differs from a fresh evaluation of its inputs")
    if not fresh["passed"]:
        named = [f"{row['id']}: " + "; ".join(row["detail"]) for row in fresh["conditions"] if row["met"] is not True]
        raise GateInputError("performance.release is unmet: " + " | ".join(named))
    return record


def parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    evaluate = commands.add_parser("evaluate", help="read retained receipts and write NEW_DIR/receipt.json")
    evaluate.add_argument("--runtime-c-collector", type=Path, required=True)
    evaluate.add_argument("--native-facade-report", type=Path, required=True)
    evaluate.add_argument("--rustybench-source", type=Path, required=True)
    evaluate.add_argument("--rustix-source", type=Path, required=True)
    evaluate.add_argument("--allocator-report", type=Path, action="append", default=[], required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate", help="reread one retained gate receipt")
    validate.add_argument("--receipt", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        if arguments.command == "validate":
            validate_receipt(ROOT, arguments.receipt)
            print(f"x86 performance.release receipt: PASS ({arguments.receipt})")
            return 0
        receipt = build_receipt(collect_inputs(arguments))
        path = write_receipt(arguments.output, receipt)
    except GateInputError as error:
        print(f"x86 performance.release: ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps(receipt["conditions"], indent=2, sort_keys=True))
    print(f"x86 performance.release receipt: {_checkout_path(path)}")
    if receipt["passed"]:
        print("x86 performance.release: PASS")
        return 0
    print(f"x86 performance.release: UNMET ({', '.join(receipt['unmet'])})")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
