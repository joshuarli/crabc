#!/usr/bin/env python3
"""Read-only native Linux/x86-64 allocator evidence gate.

The gate requires a complete matrix, three distinct qualified reports with
matching source, configuration, host and built products, a complete codegen
audit without Rust-only structural cost, source convergence, one qualified
integrated-product report, and current correctness gate reports. It measures
nothing and names every unmet condition. Numerical promotion thresholds are
applied separately to the qualified reports' metrics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import perf_engine_x86_64 as engine
import perf_integrated_x86_64 as integrated
import run as harness
import source_convergence


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
CORRECTNESS_INPUTS = {
    "m4": ("x86_64_m4_gate.py", "m4-gate-x86_64-v3.5.0.json"),
    "m5": ("x86_64_m5_gate.py", "m5-gate-x86_64-v3.5.0.json"),
    "m6": ("m6_gate.py", "m6-gate-v3.5.0.json"),
    "m7": ("x86_64_m7_gate.py", "m7-gate-x86_64-v3.5.0.json"),
}
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m9-gate"
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
    covered = [record["path"] for record in records if not record["unmet"] and record.get("coverage") == {}]
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
    seen_paths: set[Path] = set()
    seen_labels: set[str] = set()
    seen_attempts: set[str] = set()
    for path in paths:
        canonical = Path(path).resolve()
        if canonical in seen_paths:
            records.append({"path": harness.relative(Path(path)), "unmet": ["report path repeats an earlier attempt"],
                            "identity": None, "metrics": None})
            continue
        seen_paths.add(canonical)
        try:
            inspected = dict(inspect(harness.ROOT, path))
        except Exception as error:  # noqa: BLE001 - a reader refusal is the unmet detail
            inspected = {"unmet": [f"{type(error).__name__}: {error}"], "identity": None, "metrics": None}
        if not inspected.get("unmet"):
            try:
                attempt = retained_attempt(Path(path))
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
                inspected["unmet"] = [f"retained attempt identity is invalid: {error}"]
            else:
                if attempt["label"] in seen_labels:
                    inspected["unmet"] = [f"attempt label {attempt['label']!r} repeats an earlier report"]
                elif attempt["fingerprint"] in seen_attempts:
                    inspected["unmet"] = ["raw report duplicates an earlier attempt apart from its label"]
                else:
                    seen_labels.add(attempt["label"])
                    seen_attempts.add(attempt["fingerprint"])
                    inspected["product_identity"] = attempt["products"]
        records.append({"path": harness.relative(Path(path)), **inspected})
    return records


def retained_attempt(path: Path) -> dict[str, Any]:
    """Read the retained measurement's label, built products, and raw attempt content."""

    report = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("label") != path.stem:
        raise ValueError("report label differs from its retained filename")
    lanes = report["lanes"]
    rust_library = lanes["rust_engine"]["static_library"]
    physical_library = path.with_suffix(".artifacts") / "libcrabc_allocator_engine_rust_backend.a"
    if (not physical_library.is_file() or physical_library.is_symlink()
            or rust_library != engine.artifact_record(physical_library)):
        raise ValueError("Rust static library differs from its retained physical product")
    products = {
        "shared_fixture_object": lanes["shared_fixture_object_sha256"],
        "pinned_c_executable": lanes["pinned_c"]["executable"]["artifact"]["sha256"],
        "rust_engine_static_library": rust_library["sha256"],
        "rust_engine_executable": lanes["rust_engine"]["executable"]["artifact"]["sha256"],
    }
    if any(not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
           for digest in products.values()):
        raise ValueError("retained product identity lacks a SHA-256 digest")
    without_label = {key: value for key, value in report.items() if key != "label"}
    fingerprint = hashlib.sha256(json.dumps(without_label, sort_keys=True, separators=(",", ":"),
                                          allow_nan=False).encode("utf-8")).hexdigest()
    return {"label": report["label"], "products": products, "fingerprint": fingerprint}


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
            if record.get("product_identity") != first.get("product_identity"):
                unmet.append(f"{record['path']} built product identity differs from {first['path']}")
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


def convergence_condition(evaluate_convergence: Callable[[Path], Sequence[Mapping[str, Any]]]) -> dict[str, Any]:
    try:
        rows = evaluate_convergence(harness.ROOT)
    except Exception as error:  # noqa: BLE001
        return _condition("m9.source-convergence", [f"{type(error).__name__}: {error}"], "")
    unmet = [f"{row['id']}: {item}" for row in rows if not row["met"] for item in row["detail"]]
    return _condition("m9.source-convergence", unmet, "every source-convergence condition is met")


def discover_integrated(directory: Path = integrated.REPORT_ROOT) -> list[Path]:
    return sorted(directory.glob("*.json")) if directory.is_dir() else []


def integrated_condition(
    paths: Sequence[Path], inspect: Callable[[Path, Path], Mapping[str, Any]],
    cohort: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """One physical integrated comparison must belong to the qualified engine cohort."""

    unmet: list[str] = []
    accepted = []
    agreement = agreement_condition(cohort)
    if not agreement["met"]:
        unmet.append("integrated products need three agreeing qualified engine reports")
    for path in paths:
        try:
            result = inspect(harness.ROOT, path)
        except Exception as error:  # noqa: BLE001
            result = {"unmet": [f"{type(error).__name__}: {error}"]}
        if not isinstance(result, Mapping) or not isinstance(result.get("unmet"), list):
            result = {"unmet": ["integrated reader returned no valid refusal list"]}
        if not result["unmet"]:
            metrics = result.get("metrics")
            fields = {"throughput_lower_95", "p99_upper_95", "peak_rss_upper_95", "peak_pss_upper_95"}
            names = set(integrated.row_names(integrated.load_manifest()))
            if (not isinstance(metrics, Mapping) or set(metrics) != names
                    or any(not isinstance(row, Mapping) or set(row) != fields
                           or any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0
                                  for value in row.values()) for row in metrics.values())):
                result = {"unmet": ["integrated reader returned no complete row metrics"]}
        if result["unmet"]:
            unmet.append(f"{harness.relative(Path(path))}: " + "; ".join(result["unmet"]))
        else:
            try:
                report = json.loads(Path(path).read_text(encoding="utf-8"))
                physical_unmet = physical_integrated_unmet(Path(path), report)
                if agreement["met"]:
                    if not same_cohort_host(report["provenance"]["host"], cohort[0]["identity"]["host"]):
                        physical_unmet.append("host identity differs from the qualified engine reports")
            except Exception as error:  # noqa: BLE001 - malformed retained evidence must fail closed
                physical_unmet = [f"retained integrated product is invalid: {type(error).__name__}: {error}"]
            if physical_unmet:
                unmet.append(f"{harness.relative(Path(path))}: " + "; ".join(physical_unmet))
            elif agreement["met"]:
                accepted.append(path)
    if not accepted:
        unmet.insert(0, f"no qualified integrated-product report among {len(paths)} read "
                        "(allocator-perf-integrated --full)")
        return _condition("m9.integrated-products", unmet, "")
    return _condition("m9.integrated-products", [], f"{harness.relative(Path(accepted[0]))} qualifies")


def same_cohort_host(integrated_host: Mapping[str, Any], engine_host: Mapping[str, Any]) -> bool:
    """A narrower integrated CPU set may share the engine cohort's physical host."""

    stable_fields = ("cpu_model", "kernel_release", "logical_cpus", "allowed_cpus", "transparent_hugepage")
    if any(integrated_host.get(field) != engine_host.get(field) for field in stable_fields):
        return False
    measured = integrated_host.get("measurement_cpus")
    cohort_cpus = engine_host.get("measurement_cpus")
    if (not isinstance(measured, list) or not measured or len(set(measured)) != len(measured)
            or not isinstance(cohort_cpus, list) or not set(measured) <= set(cohort_cpus)):
        return False
    governors = integrated_host.get("scaling_governors")
    cohort_governors = engine_host.get("scaling_governors")
    return (isinstance(governors, Mapping) and isinstance(cohort_governors, Mapping)
            and governors == {str(cpu): cohort_governors[str(cpu)] for cpu in measured
                              if str(cpu) in cohort_governors})


def physical_integrated_unmet(path: Path, report: Mapping[str, Any]) -> list[str]:
    """Reread installed products and programs from the report's retained build tree."""

    label = engine.validate_label(report["label"])
    if label != path.stem:
        return ["report label differs from its retained filename"]
    work = integrated.WORK_ROOT / label
    if work.is_symlink():
        return ["retained integrated build tree is a symlink"]
    manifest = integrated.load_manifest()
    products: dict[str, dict[str, Path]] = {}
    unmet = []
    if set(report["products"]) != {"static", "dynamic"} or set(report["programs"]) != {
            "static/pinned_c", "static/rust_engine", "dynamic/pinned_c", "dynamic/rust_engine", "launcher"}:
        return ["integrated report does not name exactly its installed products and programs"]
    for kind in ("static", "dynamic"):
        products[kind] = {}
        objects = []
        if set(report["products"][kind]) != set(manifest["backends"]):
            return [f"{kind} report does not name exactly its C and Rust installed products"]
        for lane, backend in manifest["backends"].items():
            product = work / "products" / f"{kind}-{backend}"
            products[kind][lane] = product
            product_manifest = product / "share/crabc/manifest.json"
            recorded_product = report["products"][kind][lane]
            if (product.is_symlink() or product_manifest.is_symlink() or recorded_product != {
                    "path": engine.shared.relative(product), "manifest": engine.file_record(product_manifest)}
                    or integrated.product_backend(product) != backend):
                unmet.append(f"{kind}/{lane} installed product differs from its retained manifest")
            product_contents = json.loads(product_manifest.read_text(encoding="utf-8"))
            declared_files = (product_contents.get("installed", {}).get("files") if kind == "static"
                              else product_contents.get("files"))
            declared_symlinks = {} if kind == "static" else product_contents.get("symlinks")
            files, symlinks = physical_tree(product, exclude={"share/crabc/manifest.json"})
            if (not isinstance(declared_files, dict) or files != declared_files
                    or not isinstance(declared_symlinks, dict) or symlinks != declared_symlinks):
                unmet.append(f"{kind}/{lane} installed payload differs from its manifest")
            program = work / "programs" / f"{kind}-{lane}"
            executable = program / "program"
            recorded_program = report["programs"][f"{kind}/{lane}"]
            if (program.is_symlink() or executable.is_symlink()
                    or recorded_program["executable"] != engine.artifact_record(executable)):
                unmet.append(f"{kind}/{lane} program differs from its retained executable")
            physical_objects = {}
            for name in ("engine-fixture.o", "integrated-libc-backend.o"):
                physical = program / name
                if physical.is_symlink():
                    unmet.append(f"{kind}/{lane} {name} is a symlink")
                physical_objects[name] = engine.sha256_file(physical)
            if recorded_program["objects"] != physical_objects:
                unmet.append(f"{kind}/{lane} program objects differ from their retained digests")
            if kind == "dynamic":
                runtime_files, runtime_symlinks = physical_tree(program / "root")
                expected_runtime = dict(files, **{"share/crabc/manifest.json": engine.sha256_file(product_manifest),
                                                  "program": engine.sha256_file(executable)})
                if runtime_files != expected_runtime or runtime_symlinks != symlinks:
                    unmet.append(f"{kind}/{lane} execution root differs from its installed product and program")
            objects.append(physical_objects)
        if objects[0] != objects[1]:
            unmet.append(f"{kind} C and Rust program objects are not source-identical")
    if report["c_reference"] != integrated.c_reference(products):
        unmet.append("C reference differs from the installed evidence products")
    launcher = work / "programs/integrated-startup-launcher"
    if launcher.is_symlink() or report["programs"]["launcher"] != engine.artifact_record(launcher):
        unmet.append("startup launcher differs from its retained executable")
    return unmet


def physical_tree(root: Path, *, exclude: set[str] | None = None) -> tuple[dict[str, str], dict[str, str]]:
    """Hash the regular files and relative links of a retained installed tree."""

    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"retained tree is absent or is a symlink: {root}")
    files: dict[str, str] = {}
    symlinks: dict[str, str] = {}
    for item in root.rglob("*"):
        name = item.relative_to(root).as_posix()
        if item.is_symlink():
            target = os.readlink(item)
            if Path(target).is_absolute() or ".." in Path(target).parts:
                raise ValueError(f"retained tree has an escaping symlink: {name}")
            symlinks[name] = target
        elif item.is_file():
            if name not in (exclude or set()):
                files[name] = engine.sha256_file(item)
        elif not item.is_dir():
            raise ValueError(f"retained tree has a non-file entry: {name}")
    return files, symlinks


def correctness_condition(accepted_paths: Sequence[Path], gate_root: Path = harness.ARTIFACT_ROOT / "x86_64") -> dict[str, Any]:
    unmet = ["allocator M8 has no gate in this launcher"]
    newest = max((Path(path).stat().st_mtime_ns for path in accepted_paths), default=None)
    for gate in CORRECTNESS_GATES:
        path = gate_root / f"{gate}-gate/report.json"
        if not path.is_file():
            unmet.append(f"{gate.upper()} gate has no retained report ({harness.relative(path)})")
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            status = report.get("overall_status")
        except (OSError, json.JSONDecodeError, AttributeError) as error:
            unmet.append(f"{gate.upper()} gate report is unreadable: {error}")
            continue
        if status != "passed":
            unmet.append(f"{gate.upper()} gate report is {status}")
        elif newest is not None and path.stat().st_mtime_ns < newest:
            unmet.append(f"{gate.upper()} gate report predates the newest qualified report")
        else:
            unmet.extend(f"{gate.upper()} gate {reason}" for reason in correctness_evidence_unmet(
                gate, report, path.parent, newest))
    return _condition("m9.correctness", unmet, "M4-M8 correctness gates passed after the qualified reports")


def correctness_evidence_unmet(
    gate: str, report: Mapping[str, Any], artifacts: Path, newest: int | None,
) -> list[str]:
    """Recheck source identity, complete gate coverage, and retained raw evidence."""

    if not isinstance(report.get("provenance"), Mapping):
        return ["report lacks current evidence provenance"]
    try:
        gate_file, contract_file = (harness.ALLOCATOR_ROOT / name for name in CORRECTNESS_INPUTS[gate])
        contract = json.loads(contract_file.read_text(encoding="utf-8"))
        expected_gates = [record["id"] for record in contract["gates"]]
        observed = report["gates"]
        if ([record["id"] for record in observed] != expected_gates
                or any(record["status"] != "passed" for record in observed)
                or report["unmet_required"] != []):
            return ["report lacks the complete passing gate roster"]
        evidence = report["evidence"]
        expected_evidence = {name for record in contract["gates"] for name in record["evidence"]}
        if not isinstance(evidence, Mapping) or set(evidence) != expected_evidence:
            return ["report lacks current evidence for every gate"]
        provenance = report["provenance"]
        recorded_git = provenance["git"]
        current_git = engine.git_provenance()
        if (recorded_git.get("clean") is not True or current_git.get("clean") is not True
                or recorded_git.get("head") != current_git.get("head")):
            return ["report lacks current clean checkout identity"]
        seal = provenance["seal"]
        if not isinstance(seal, Mapping) or integrated.source_seal_unmet(seal):
            return ["report lacks current source and product identity"]
        if (seal.get("gate") != engine.file_record(gate_file)
                or seal.get("contract") != engine.file_record(contract_file)):
            return ["report lacks current gate and contract identity"]
        records = provenance["evidence"]
        if not isinstance(records, Mapping) or set(records) != set(evidence):
            return ["report lacks current evidence file records"]
        for name, entry in evidence.items():
            if not isinstance(entry, Mapping) or entry.get("status") != "passed":
                return [f"evidence {name} did not pass"]
            log = harness.ROOT / entry["log"]
            if log.parent.resolve() != artifacts.resolve() or log.is_symlink() or not log.is_file():
                return [f"evidence {name} lacks its retained raw log"]
            if records[name] != engine.file_record(log):
                return [f"evidence {name} differs from its retained raw log"]
            if newest is not None and log.stat().st_mtime_ns < newest:
                return [f"evidence {name} predates the newest qualified report"]
    except Exception as error:  # noqa: BLE001 - malformed gate evidence must fail closed
        return [f"report lacks current evidence: {type(error).__name__}: {error}"]
    return []


def evaluate(
    report_paths: Sequence[Path], codegen_report: Path | None,
    inspect: Callable[[Path, Path], Mapping[str, Any]] = engine.inspect_full_report,
    gate_root: Path = harness.ARTIFACT_ROOT / "x86_64",
    integrated_reports: Sequence[Path] | None = None,
    inspect_integrated: Callable[[Path, Path], Mapping[str, Any]] = integrated.inspect_integrated_report,
    evaluate_convergence: Callable[[Path], Sequence[Mapping[str, Any]]] = source_convergence.evaluate,
) -> dict[str, Any]:
    records = read_reports(report_paths, inspect)
    accepted = [Path(path) for path, record in zip(report_paths, records) if not record["unmet"]]
    conditions = [
        matrix_condition(records),
        *report_conditions(records),
        codegen_condition(codegen_report),
        convergence_condition(evaluate_convergence),
        integrated_condition(discover_integrated() if integrated_reports is None else integrated_reports,
                             inspect_integrated, [record for record in records if not record["unmet"]]),
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
            for item in row["detail"][:20]:
                print(f"  - {item if len(item) <= 600 else item[:600] + ' ...'}")
            if len(row["detail"]) > 20:
                print(f"  - ... {len(row['detail']) - 20} more in the gate report")
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
