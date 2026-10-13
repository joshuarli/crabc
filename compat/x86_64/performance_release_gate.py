#!/usr/bin/env python3
"""Evaluate the x86 ``performance.release`` gate from retained receipts only.

This gate never measures. ``evaluate`` reads runtime C and Rust-facade evidence
through each owner's reader, applies the runtime scorecard bounds, and writes
``NEW_DIR/receipt.json`` naming every unmet condition. ``validate_receipt``
reruns that evaluation from the same inputs, so replaced evidence, a changed
owner reader, or a later source change cannot pass. The
``performance-release`` publication of ``qualification_gates.py`` selects one
receipt. The inputs are:

* the runtime C scorecard: a three-attempt ``perf-c collect`` report replayed
  by ``compat/perf/x86_64_evidence.validate_collector_report`` (the
  ``perf-c check`` reader). Its release decision must be qualified with no
  blocker. Every attempt is rechecked for CPU one-sided 95% upper bound
  <= 1.00 and marked-region and whole-process syscalls <= 2R (zero when R is
  zero); each row's paired PSS and ``memory.peak`` one-sided 95% upper bounds
  across all three attempts must also be <= 1.00. The 0.90 memory target is
  reported but does not gate;
* the native Rust-facade companion: one ``perf-native --mode full`` report
  replayed by ``compat/perf/native/x86_64_runner.validate_report``. It is a
  supporting comparison with no threshold of its own, so it must only be
  complete full-mode evidence;
Both receipts must carry an ``uncontended_host`` record,
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
sys.path.insert(0, str(ROOT / "compat" / "perf"))
import x86_64_evidence as runtime_evidence

GATE = "performance.release"
SCHEMA = "crabc.x86_64-performance-release-gate/v2"
RECEIPT_NAME = "receipt.json"

# Runtime C scorecard bounds.
RUNTIME_CPU_UPPER_MAX = 1.00
RUNTIME_MEMORY_UPPER_MAX = 1.00
RUNTIME_SYSCALL_FACTOR = 2


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


def runtime_attempt_unmet(name: str, attempt: int, row: Mapping[str, Any]) -> list[str]:
    """Recheck one attempt's CPU and syscall release bounds."""
    label = f"{name} attempt {attempt}"
    unmet: list[str] = []
    upper = _number(row.get("cpu", {}).get("one_sided_95_upper"))
    if upper is None or upper > RUNTIME_CPU_UPPER_MAX:
        unmet.append(f"{label}: CPU one-sided 95% upper bound {upper} > {RUNTIME_CPU_UPPER_MAX}")
    for scope in ("marked_region", "whole_process"):
        counts = row.get("syscalls", {}).get(scope, {})
        reference, candidate = counts.get("reference"), counts.get("candidate")
        if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0
                   for value in (reference, candidate)):
            unmet.append(f"{label}: {scope} syscall totals are absent")
        elif candidate > RUNTIME_SYSCALL_FACTOR * reference:
            unmet.append(f"{label}: {scope} syscalls {candidate} > {RUNTIME_SYSCALL_FACTOR}R={RUNTIME_SYSCALL_FACTOR * reference}")
    for metric, gate in (("cpu", row.get("cpu", {}).get("gate")),
                         ("syscalls", row.get("syscalls", {}).get("gate"))):
        if gate != "pass":
            unmet.append(f"{label}: {metric} release gate is {gate}")
    return unmet


def runtime_row_unmet(name: str, row: Mapping[str, Any]) -> list[str]:
    """Recheck one row's per-attempt gates and aggregate memory bounds."""
    unmet: list[str] = []
    if row.get("gate") != "pass":
        unmet.append(f"{name}: row release gate is {row.get('gate')}")
    attempts = row.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        unmet.append(f"{name}: scorecard attempts are absent")
    else:
        expected_attempts = runtime_evidence.COLLECTOR_ATTEMPTS
        if len(attempts) != expected_attempts:
            unmet.append(f"{name}: scorecard has {len(attempts)} attempts; expected {expected_attempts}")
        for index, attempt in enumerate(attempts, start=1):
            if not isinstance(attempt, Mapping):
                unmet.append(f"{name} attempt {index}: scorecard row is not an object")
            else:
                unmet.extend(runtime_attempt_unmet(name, index, attempt))

    memory = row.get("memory")
    if not isinstance(memory, Mapping):
        return [*unmet, f"{name}: memory confidence summaries are absent"]
    for metric, label in (("pss_kib", "PSS"), ("memory_peak_bytes", "memory.peak")):
        summary = memory.get(metric)
        if not isinstance(summary, Mapping):
            unmet.append(f"{name}: {label} memory confidence summary is absent")
            continue
        upper = _number(summary.get("one_sided_95_upper"))
        if upper is None or upper > RUNTIME_MEMORY_UPPER_MAX:
            unmet.append(f"{name}: {label} one-sided 95% upper bound {upper} > {RUNTIME_MEMORY_UPPER_MAX}")
        if summary.get("release_gate") != "pass":
            unmet.append(f"{name}: {label} release gate is {summary.get('release_gate')}")
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
            if not isinstance(row, Mapping):
                unmet.append(f"{name}: scorecard row is not an object")
            else:
                unmet.extend(runtime_row_unmet(name, row))
        return _condition("runtime-c-scorecard", unmet, f"{len(rows)} rows pass across all three attempts")

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


def _cpu_models_by_processor(raw: bytes) -> dict[int, str]:
    """Read the processor-to-model relation from retained Linux x86 CPU information."""
    models: dict[int, str] = {}
    fields: dict[str, str] = {}
    for line in [*raw.decode("utf-8", errors="replace").splitlines(), ""]:
        if not line.strip():
            if fields:
                if set(fields) != {"processor", "model name"}:
                    raise GateInputError("retained CPU information lacks a processor or model name")
                try:
                    cpu = int(fields["processor"])
                except ValueError as error:
                    raise GateInputError("retained CPU information has an invalid processor number") from error
                if cpu < 0 or cpu in models or not fields["model name"]:
                    raise GateInputError("retained CPU information has duplicate or empty CPU identity")
                models[cpu] = fields["model name"]
                fields = {}
            continue
        key, separator, value = line.partition(":")
        key = key.strip()
        if separator and key in {"processor", "model name"}:
            if key in fields:
                raise GateInputError("retained CPU information repeats a processor identity field")
            fields[key] = value.strip()
    if not models:
        raise GateInputError("retained CPU information has no processor models")
    return models


def performance_identity_condition(inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Join runtime C and facade measurements by stable host facts."""

    evidence = _module(ROOT / "compat" / "perf", "x86_64_evidence")
    collector = _read_json(inputs["runtime_c_collector"]["path"])
    native = _read_json(inputs["native_facade"]["report"]["path"])
    native_diagnostics = native["diagnostics"]
    native_cpuinfo = (ROOT / _checkout_path(native_diagnostics["cpuinfo"]["path"])).read_bytes()
    native_cpu_identity = evidence.cpuinfo_identity_sha256(native_cpuinfo)
    cpu_models = _cpu_models_by_processor(native_cpuinfo)
    native_model = cpu_models.get(native_diagnostics["client_cpu"])
    unmet: set[str] = set()
    for item in collector["attempts"]:
        path = evidence.translate_source_path(ROOT, evidence.SOURCE_MOUNT, item["report"]["path"])
        attempt = json.loads(path.read_text(encoding="utf-8"))
        tools = attempt["tools"]
        host = tools["before"]["host"]
        runtime_models = tools["host_cpuinfo_diagnostics"]["before"]["model_names"]
        runtime_model = cpu_models.get(host["benchmark_cpu"])
        if host["cpuinfo_sha256"] != native_cpu_identity:
            unmet.add(f"{path}: native facade and runtime C CPU identities differ")
        if runtime_models != list(cpu_models.values()):
            unmet.add(f"{path}: runtime CPU model inventory differs from retained CPU information")
        if runtime_model is None or native_model is None or runtime_model != native_model:
            unmet.add(f"{path}: native facade and runtime C selected CPU models differ")
        if host["allowed_affinity_before_pin"] != native_diagnostics["allowed_affinity"]:
            unmet.add(f"{path}: native facade and runtime C allowed CPU sets differ")
    return _condition("performance-evidence-identity", sorted(unmet),
                      "runtime C and native facade host identities agree")


# ---------------------------------------------------------------------------
# Receipt


def evaluate_inputs(inputs: Mapping[str, Any]) -> list[dict[str, Any]]:
    native = inputs["native_facade"]
    rows = [
        *runtime_c_conditions(inputs["runtime_c_collector"]["path"]),
        *native_facade_conditions(native["report"]["path"], native["rustybench_source"], native["rustix_source"]),
    ]
    if all(row["met"] for row in rows):
        rows.append(_guard("performance-evidence-identity", lambda: performance_identity_condition(inputs)))
    return rows


def collect_inputs(arguments: argparse.Namespace) -> dict[str, Any]:
    return {
        "runtime_c_collector": _file_identity(_checkout_path(arguments.runtime_c_collector)),
        "native_facade": {
            "report": _file_identity(_checkout_path(arguments.native_facade_report)),
            "rustybench_source": _checkout_path(arguments.rustybench_source),
            "rustix_source": _checkout_path(arguments.rustix_source),
        },
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
    files = [inputs["runtime_c_collector"], inputs["native_facade"]["report"]]
    changed = [item["path"] for item in files if _file_identity(_checkout_path(item["path"])) != item]
    if changed:
        raise GateInputError("performance-release inputs changed after evaluation: " + ", ".join(changed))
    fresh = build_receipt(inputs)
    # Failed details may spell host or container paths. A passing receipt has
    # stable details and must retain exactly what the replayed readers returned.
    def verdicts(value: Mapping[str, Any]) -> list[tuple[object, object]]:
        return [(row.get("id"), row.get("met")) for row in value["conditions"]]

    if (verdicts(fresh) != verdicts(record)
            or (fresh["unmet"], fresh["passed"]) != (record["unmet"], record["passed"])
            or (fresh["passed"] and fresh["conditions"] != record["conditions"])):
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
