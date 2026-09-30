#!/usr/bin/env python3
"""Native Linux/x86-64 allocator evidence gate.

The gate requires a complete matrix, three distinct qualified reports with
matching source, configuration, host and built products, a complete codegen
audit without Rust-only structural cost, source convergence, one qualified
integrated-product report, and current correctness gate reports. It names
every unmet condition. Numerical promotion thresholds are applied separately
to the qualified reports' metrics.
The codegen condition replays retained executables to check executed traces;
it does not take a performance measurement.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import perf_engine_x86_64 as engine
import perf_integrated_x86_64 as integrated
import run as harness
import source_convergence
import divergence_evidence


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
M8_REPORT = harness.REPORT_ROOT / "x86_64/m8-gate/report.json"
M8_COMMAND_ONLY_EVIDENCE = frozenset({
    "product:c-allocation-interposition", "product:stdio-allocator-interposition",
    "product:package-corpus-input",
})
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


def codegen_condition(path: Path | None, cohort: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    if path is None:
        return _condition("m9.codegen-audit", ["no allocator-codegen-audit report exists"], "")
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
        import codegen_audit_x86_64 as codegen

        unmet = codegen_unmet(report, [scenario.name for scenario in codegen.SCENARIOS])
        if not agreement_condition(cohort)["met"]:
            unmet.append("codegen audit needs three agreeing qualified engine reports")
        else:
            unmet.extend(physical_codegen_unmet(Path(path), report, codegen, cohort[0]))
    except Exception as error:  # noqa: BLE001
        unmet = [f"{type(error).__name__}: {error}"]
    return _condition("m9.codegen-audit", [f"{harness.relative(Path(path))}: {item}" for item in unmet],
                      f"{harness.relative(Path(path))} has no Rust-only structural cost")


def physical_codegen_unmet(path: Path, report: Mapping[str, Any], codegen: Any,
                           cohort: Mapping[str, Any]) -> list[str]:
    """Recompute the audit from retained engine products and instruction listings."""

    label = engine.validate_label(report["label"])
    if (path.is_symlink() or label != path.stem or report.get("schema") != codegen.SCHEMA
            or report.get("kind") != codegen.KIND):
        return ["codegen report path or schema differs from its retained audit"]
    artifacts = path.with_suffix(".artifacts")
    if not artifacts.is_dir() or artifacts.is_symlink():
        return ["codegen audit lacks its retained artifacts"]
    provenance = report["provenance"]
    inputs = provenance["inputs"]
    source = dict(inputs, mimalloc={key: inputs["mimalloc"][key] for key in ("version", "tag", "revision")}
                  | {"archive_sha256": inputs["mimalloc"]["archive"]["sha256"]})
    if source != cohort["identity"]["source"]:
        return ["codegen audit source differs from the qualified engine reports"]
    if provenance.get("tools") != cohort["identity"]["configuration"].get("tools"):
        return ["codegen audit tool configuration differs from the qualified engine reports"]
    current_git = engine.git_provenance()
    if (current_git.get("clean") is not True or provenance["git"].get("head") != current_git.get("head")):
        return ["codegen audit checkout revision differs from this clean checkout"]
    products = cohort["product_identity"]
    names = {"pinned_c": "engine-fixture-pinned-c", "rust_engine": "engine-fixture-rust-engine"}
    if set(report["lanes"]) != set(names) or set(report["static"]) != set(names):
        return ["codegen audit omits a C or Rust product"]
    images = {}
    unmet = []
    for lane, name in names.items():
        executable = artifacts / name
        if executable.is_symlink() or not executable.is_file():
            unmet.append(f"{lane} codegen executable is absent or redirected")
            continue
        recorded = report["lanes"][lane]["executable"]
        expected = {"artifact": engine.artifact_record(executable), "elf": dict(engine.shared.EXPECTED_ELF),
                    "type": "static-non-pie-exec"}
        cohort_key = "pinned_c_executable" if lane == "pinned_c" else "rust_engine_executable"
        if recorded != expected or expected["artifact"]["sha256"] != products[cohort_key]:
            unmet.append(f"{lane} codegen executable differs from the qualified engine product")
            continue
        images[lane] = codegen.Image(executable, "nm", "objdump")
    for name, digest in (("engine-fixture-c.o", products["shared_fixture_object"]),
                         ("engine-fixture-rust.o", products["shared_fixture_object"]),
                         ("libcrabc_allocator_engine_rust_backend.a", products["rust_engine_static_library"])):
        physical = artifacts / name
        if physical.is_symlink() or not physical.is_file() or engine.sha256_file(physical) != digest:
            unmet.append(f"codegen product {name} differs from the qualified engine product")
    if set(images) != set(names):
        return unmet
    for lane, image in images.items():
        if set(report["static"][lane]) != set(codegen.ENTRY_SYMBOLS):
            unmet.append(f"{lane} codegen static reachability omits an entry")
            continue
        for entry in codegen.ENTRY_SYMBOLS:
            if report["static"][lane][entry] != codegen.static_reachability(image, entry):
                unmet.append(f"{lane} codegen static reachability differs from its executable")
    if set(report["scenarios"]) != {scenario.name for scenario in codegen.SCENARIOS}:
        unmet.append("codegen audit scenario roster differs from the complete audit")
        return unmet
    scratch_root = harness.ROOT / ".work"
    scratch_root.mkdir(exist_ok=True)
    cpu = min(os.sched_getaffinity(0))
    for scenario in codegen.SCENARIOS:
        record = report["scenarios"][scenario.name]
        if (record.get("workload") != scenario.workload or record.get("params") != dict(scenario.params)
                or record.get("measures") != scenario.measures or set(record.get("lanes", {})) != set(names)
                or set(record.get("comparison", {})) != set(scenario.regions)):
            unmet.append(f"codegen {scenario.name} does not describe the selected trace")
            continue
        with tempfile.TemporaryDirectory(prefix="codegen-replay-", dir=scratch_root) as temporary:
            observed = {lane: codegen.trace_scenario(artifacts / names[lane], images[lane], scenario,
                                                      Path(temporary), cpu) for lane in names}
        for region_index, region in enumerate(scenario.regions):
            for lane in names:
                summary = record["lanes"][lane][region]
                listing = artifacts / f"trace-{scenario.name}-{region}-{lane}.txt"
                if summary.get("listing") != listing.name or listing.is_symlink() or not listing.is_file():
                    unmet.append(f"codegen {scenario.name}/{region}/{lane} lacks its retained listing")
                    continue
                rips = []
                for line in listing.read_text(encoding="utf-8").splitlines():
                    match = re.fullmatch(r"(0x[0-9a-f]+) (.+?): (.+?)(?:  x([1-9][0-9]*))?", line)
                    if match is None:
                        raise ValueError(f"malformed codegen listing: {listing.name}")
                    address, function, instruction, repeats = match.groups()
                    address = int(address, 16)
                    item = images[lane].instructions.get(address)
                    expected_instruction = item.text if item is not None else "<no disassembly>"
                    if (images[lane].function_at(address) != function
                            or expected_instruction != instruction):
                        unmet.append(f"codegen {scenario.name}/{region}/{lane} listing differs from its executable")
                        break
                    rips.extend([address] * (int(repeats) if repeats else 1))
                else:
                    recomputed, _ = codegen.analyze_region(images[lane], codegen.Region(rips, {}))
                    if any(summary.get(key) != value for key, value in recomputed.items()
                           if key not in ("atomic_rmw_targets", "atomic_rmw_non_thread_local")):
                        unmet.append(f"codegen {scenario.name}/{region}/{lane} summary differs from its listing")
                    replayed = observed[lane][region_index]
                    replay_source, replay_spans = codegen.project_region(images[lane], replayed)
                    raw = artifacts / f"trace-{scenario.name}-{region}-{lane}.json"
                    if raw.is_symlink() or not raw.is_file():
                        unmet.append(f"codegen {scenario.name}/{region}/{lane} lacks its retained raw trace")
                    else:
                        raw_record = json.loads(raw.read_text(encoding="utf-8"))
                        retained_vdso = (codegen.VdsoImage(**raw_record["vdso"])
                                         if "vdso" in raw_record else None)
                        retained_source, retained_spans = codegen.project_region(
                            images[lane], codegen.Region(raw_record["rips"], {}, retained_vdso))
                        if rips != retained_source.rips:
                            unmet.append(f"codegen {scenario.name}/{region}/{lane} listing differs from raw executable steps")
                        if (raw_record.get("external_vdso") != retained_spans
                                or summary.get("external_vdso") != retained_spans):
                            unmet.append(f"codegen {scenario.name}/{region}/{lane} external observations differ from raw trace")
                        if retained_source.rips != replay_source.rips:
                            first = next((index for index, (retained, actual) in enumerate(zip(
                                retained_source.rips, replay_source.rips)) if retained != actual),
                                min(len(retained_source.rips), len(replay_source.rips)))
                            unmet.append(f"codegen {scenario.name}/{region}/{lane} executed trace differs from replay "
                                         f"at executable step {first}")
                        retained_boundaries = [{key: value for key, value in span.items() if key != "steps"}
                                               for span in retained_spans]
                        replay_boundaries = [{key: value for key, value in span.items() if key != "steps"}
                                             for span in replay_spans]
                        if (retained_boundaries != replay_boundaries
                                or (retained_vdso.sha256 if retained_vdso else None)
                                != (replayed.vdso.sha256 if replayed.vdso else None)):
                            unmet.append(f"codegen {scenario.name}/{region}/{lane} external clock boundary or image differs from replay")
                        recorded_targets = codegen.projected_atomic_events(
                            images[lane], raw_record["rips"], raw_record["atomic_targets"])
                        replay_targets = codegen.projected_atomic_events(
                            images[lane], replayed.rips, codegen.trace_record(images[lane], replayed)["atomic_targets"])
                        if recorded_targets != replay_targets:
                            unmet.append(f"codegen {scenario.name}/{region}/{lane} raw atomic trace differs from replay")
                    replay_summary, _ = codegen.analyze_region(images[lane], replay_source)
                    if (summary.get("atomic_rmw_targets") != replay_summary["atomic_rmw_targets"]
                            or summary.get("atomic_rmw_non_thread_local")
                            != replay_summary["atomic_rmw_non_thread_local"]):
                        unmet.append(f"codegen {scenario.name}/{region}/{lane} atomic targets differ from replay")
                    targets = summary.get("atomic_rmw_targets")
                    if (not isinstance(targets, Mapping) or any(type(value) is not int or value < 0
                                                                 for value in targets.values())
                            or summary.get("atomic_rmw_non_thread_local") != sum(
                                value for name, value in targets.items() if name not in {"thread-local", "stack"})):
                        unmet.append(f"codegen {scenario.name}/{region}/{lane} atomic targets are inconsistent")
            if (record["comparison"][region] != codegen.compare_regions(
                    record["lanes"]["pinned_c"][region], record["lanes"]["rust_engine"][region])):
                unmet.append(f"codegen {scenario.name}/{region} comparison differs from its lane summaries")
    return unmet


def convergence_condition(
    evaluate_convergence: Callable[[Path], Sequence[Mapping[str, Any]]],
    engine_paths: Sequence[Path] = (),
    integrated_paths: Sequence[Path] = (),
    gate_root: Path = harness.ARTIFACT_ROOT / "x86_64",
) -> dict[str, Any]:
    """Read current convergence inputs and require their physical evidence cohort."""

    try:
        rows = source_convergence.evaluate(harness.ROOT)
        supplied = evaluate_convergence(harness.ROOT)
        manifest, _ = divergence_evidence.load()
        physical_records = read_reports(engine_paths, engine.inspect_full_report)
    except Exception as error:  # noqa: BLE001
        return _condition("m9.source-convergence", [f"{type(error).__name__}: {error}"], "")
    unmet = [f"{row['id']}: {item}" for row in rows if not row["met"] for item in row["detail"]]
    if supplied != rows:
        unmet.append("convergence verdict differs from the current port map and known differences")
    cohort = [record for record in physical_records if not record["unmet"]]
    engine_rows = set()
    if agreement_condition(cohort)["met"] and matrix_condition(physical_records)["met"]:
        timed, memory = engine.selected_rows(engine.load_manifest(), engine.QUALIFIED_ROW_SET)
        engine_rows = {row["name"] for row in (*timed, *memory)}
    integrated_result = integrated_condition(integrated_paths, integrated.inspect_integrated_report, cohort)
    integrated_rows = (set(integrated.row_names(integrated.load_manifest()))
                       if integrated_result["met"] else set())
    newest = max((Path(path).stat().st_mtime_ns for path, record in zip(engine_paths, physical_records)
                  if not record["unmet"]), default=None)
    for key, entry in sorted(manifest["rows"].items()):
        if "owner" in entry:
            unmet.append(f"{key}: differential evidence is still owned by {entry['owner']}")
            continue
        differential = entry["differential"]
        if "command" in differential:
            reason = convergence_differential_unmet(differential["command"], gate_root, newest)
            if reason:
                unmet.append(f"{key}: {reason}")
        performance = entry["performance"]
        if "blocked" in performance:
            unmet.append(f"{key}: performance remains blocked: {performance['blocked']}")
        for group, available in (("engine_rows", engine_rows), ("integrated_rows", integrated_rows)):
            missing = sorted(set(performance.get(group, [])) - available)
            if missing:
                unmet.append(f"{key}: no qualified source-bound {group} report measures {missing}")
    return _condition("m9.source-convergence", unmet, "every source-convergence condition is met")


def convergence_differential_unmet(command: Sequence[str], gate_root: Path, newest: int | None) -> str | None:
    """Find an executed differential in a current source-sealed correctness gate."""

    matches = []
    try:
        for gate, (_, contract_name) in CORRECTNESS_INPUTS.items():
            contract = json.loads((harness.ALLOCATOR_ROOT / contract_name).read_text(encoding="utf-8"))
            for evidence_id, declared in contract["evidence"].items():
                if (declared.get("command") == list(command)
                        or ("runner" in declared and ["python3", declared["runner"]] == list(command))):
                    matches.append((gate, evidence_id, declared))
    except Exception as error:  # noqa: BLE001 - malformed current contracts cannot prove a differential
        return f"current differential gate contract is unreadable: {type(error).__name__}: {error}"
    if not matches:
        return f"no source/fixture/program-bound retained differential receipt for {' '.join(command)}"
    for gate, evidence_id, declared in matches:
        path = gate_root / f"{gate}-gate/report.json"
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            if report.get("overall_status") != "passed" or correctness_evidence_unmet(gate, report, path.parent, newest):
                continue
            recorded = report["evidence"][evidence_id]
            if declared.get("runner") is not None and recorded.get("runner") != declared["runner"]:
                continue
            if declared.get("command") is not None and recorded.get("command") != list(command):
                continue
            return (f"{gate.upper()} gate ran {' '.join(command)}, but its retained evidence lacks "
                    "independently checkable C/Rust fixture and executable identities")
        except Exception:  # noqa: BLE001 - a malformed retained gate cannot prove the differential
            continue
    gates = ", ".join(sorted({gate.upper() for gate, _, _ in matches}))
    return f"no current source/fixture/program-bound {gates} differential receipt for {' '.join(command)}"


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


def correctness_condition(
    accepted_paths: Sequence[Path], gate_root: Path = harness.ARTIFACT_ROOT / "x86_64",
    m8_report_path: Path = M8_REPORT,
) -> dict[str, Any]:
    unmet: list[str] = []
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
    if not m8_report_path.is_file() or m8_report_path.is_symlink():
        unmet.append(f"M8 gate has no retained report ({harness.relative(m8_report_path)})")
    else:
        try:
            report = json.loads(m8_report_path.read_text(encoding="utf-8"))
            status = report.get("overall_status")
        except (OSError, json.JSONDecodeError, AttributeError) as error:
            unmet.append(f"M8 gate report is unreadable: {error}")
        else:
            if status != "passed":
                unmet.append(f"M8 gate report is {status}")
            elif newest is not None and m8_report_path.stat().st_mtime_ns < newest:
                unmet.append("M8 gate report predates the newest qualified report")
            else:
                unmet.extend(f"M8 gate {reason}" for reason in m8_evidence_unmet(report, m8_report_path, newest))
    return _condition("m9.correctness", unmet, "M4-M8 correctness gates passed after the qualified reports")


def read_m8_receipt(name: str, entry: Mapping[str, Any], output: str) -> dict[str, Any]:
    """Reread one retained integration receipt with its producer's validator."""

    import x86_64_m8_gate as m8

    command = entry["command"]
    receipt = entry["receipt"]
    if name == "product:native-allocator-policy":
        return m8.read_native_allocator_policy_receipt(command, output)
    if name == "consumer:rust-std-lto":
        return m8.read_native_shadow_receipt(command, m8.qualification.source_digest())
    if name.startswith("consumer:lua-"):
        return m8.read_lua_evidence(name.removeprefix("consumer:lua-"), Path(receipt["path"]))
    if name == "product:package-corpus":
        position = command.index("--dynamic-sysroot")
        # The loader reader may already have imported a different run_x86 module.
        # A fresh interpreter gives the corpus reader its own module namespace.
        try:
            result = subprocess.run(
                [sys.executable, "-B", str(Path(m8.__file__).resolve()), "--read-corpus-evidence",
                 receipt["path"], command[position + 1]],
                cwd=harness.ROOT, capture_output=True, text=True,
                timeout=m8.EVIDENCE_TIMEOUT_SECONDS, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise harness.HarnessError(f"corpus physical receipt reader failed: {error}") from error
        if result.returncode != 0:
            raise harness.HarnessError("corpus physical receipt reader failed: " + result.stderr[-1000:])
        try:
            reread = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise harness.HarnessError(f"corpus physical receipt reader returned invalid JSON: {error}") from error
        if not isinstance(reread, dict):
            raise harness.HarnessError("corpus physical receipt reader returned no receipt")
        return reread
    if name in {"product:native-worker-lifecycle", "product:native-allocator-fork",
                "product:native-allocator-stress"}:
        return m8.read_threads_fork_receipt(name, command, output)
    if name == "product:native-worker-transfer":
        return m8.worker_transfer.read_receipt(output)
    if name == "product:allocator-override":
        return m8.read_allocator_override_receipt(command, output)
    if name == "product:mimalloc-startup-errno":
        return m8.read_startup_constructor_receipt(command, output)
    if name in {"product:native-allocator-dso", "product:loader-synthetic",
                "product:loader-libc-identity"}:
        return m8.read_dso_loader_receipt(name, command, output)
    raise ValueError(f"no physical integration reader for {name}")


def m8_evidence_unmet(report: Mapping[str, Any], path: Path, newest: int | None) -> list[str]:
    """Bind the integration gate's existing readers to its retained logs and receipts."""

    import x86_64_m8_gate as m8

    try:
        contract, summary = m8.load_summary()
        evidence = report["evidence"]
        if (report.get("contract") != harness.relative(m8.CONTRACT)
                or not isinstance(evidence, Mapping)
                or set(evidence) != set(summary["runnable_evidence"])
                or report.get("gates") != m8.gate_report(contract, summary, evidence)["gates"]
                or report.get("unmet_required") != []):
            return ["report lacks the complete passing integration roster"]
        current_git = engine.git_provenance()
        if current_git.get("clean") is not True:
            return ["report lacks a current clean checkout"]
        source = m8.qualification.source_digest()
        producer = summary["products"]["evidence"]
        producer_log = path.parent / f"{producer.replace(':', '-')}.log"
        if not producer_log.is_file() or producer_log.is_symlink():
            return ["native-shadow product log is not physical"]
        directory = m8.product_directory(producer_log.read_text(encoding="utf-8"),
                                         summary["products"]["evidence_line"])
        if directory is None:
            return ["native-shadow product root is missing from its log"]
        for name, canonical in summary["runnable_evidence"].items():
            entry = evidence[name]
            expected_command = (m8.bind_products(canonical, summary["products"], directory)
                                if m8._uses_products(canonical) else canonical)
            log = path.parent / f"{name.replace(':', '-')}.log"
            if (not isinstance(entry, Mapping) or entry.get("status") != "passed"
                    or entry.get("command") != expected_command
                    or entry.get("log") != harness.relative(log)):
                return [f"evidence {name} lacks its passing canonical command"]
            if not log.is_file() or log.is_symlink():
                return [f"evidence {name} lacks its physical raw log"]
            if newest is not None and log.stat().st_mtime_ns < newest:
                return [f"evidence {name} predates the newest qualified report"]
            receipt = entry.get("receipt")
            if name in M8_COMMAND_ONLY_EVIDENCE:
                if receipt is not None:
                    return [f"evidence {name} unexpectedly claims a physical receipt"]
                continue
            if not isinstance(receipt, Mapping):
                return [f"evidence {name} lacks its physical receipt"]
            receipt_path = Path(receipt["path"])
            if not receipt_path.is_absolute():
                receipt_path = harness.ROOT / receipt_path
            if (not receipt_path.is_file() or receipt_path.is_symlink()
                    or engine.sha256_file(receipt_path) != receipt.get("sha256")):
                return [f"evidence {name} physical receipt differs"]
            if name.startswith("consumer:lua-"):
                if receipt.get("source_identity") != {"revision": current_git["head"],
                                                      "source_sha256": source}:
                    return [f"evidence {name} lacks current source identity"]
            elif receipt.get("source_sha256") != source:
                return [f"evidence {name} lacks current source identity"]
            reread = read_m8_receipt(name, entry, log.read_text(encoding="utf-8"))
            reread_path = Path(reread["path"])
            if not reread_path.is_absolute():
                reread_path = harness.ROOT / reread_path
            if (not reread_path.is_relative_to(harness.ROOT / ".work")
                    or not reread_path.is_file() or reread_path.is_symlink()
                    or not receipt_path.samefile(reread_path)
                    or {**reread, "path": receipt["path"]} != receipt):
                return [f"evidence {name} differs from its physical receipt"]
    except Exception as error:  # noqa: BLE001 - a rejected integration receipt must fail closed
        return [f"report lacks current physical evidence: {type(error).__name__}: {error}"]
    return []


def correctness_evidence_unmet(
    gate: str, report: Mapping[str, Any], artifacts: Path, newest: int | None, *,
    qualification_profile: str = "full",
) -> list[str]:
    """Reconstruct contract classification and recheck source and retained raw evidence."""

    if qualification_profile not in {"full", "correctness"} or (gate != "m5" and qualification_profile != "full"):
        return ["unsupported correctness evidence profile"]
    if gate == "m5":
        if report.get("qualification_profile", "full") != qualification_profile:
            return (["report lacks the complete passing gate roster"] if qualification_profile == "full"
                    else ["report qualification profile differs from the requested profile"])
        if qualification_profile == "correctness":
            expected = harness.ARTIFACT_ROOT / "x86_64/m5-correctness-gate"
            if artifacts.resolve() != expected.resolve():
                return ["correctness report is outside its dedicated artifact directory"]
            if (report.get("performance_qualified") is not False
                    or report.get("deferred_gate_ids") != ["m5.codegen-performance"]):
                return ["correctness profile has invalid performance or deferred gate claims"]
    if not isinstance(report.get("provenance"), Mapping):
        return ["report lacks current evidence provenance"]
    try:
        gate_file, contract_file = (harness.ALLOCATOR_ROOT / name for name in CORRECTNESS_INPUTS[gate])
        contract = json.loads(contract_file.read_text(encoding="utf-8"))
        expected_gates = [record["id"] for record in contract["gates"]]
        observed = report["gates"]
        if ([record["id"] for record in observed] != expected_gates
                or any(record["status"] != ("deferred" if gate == "m5" and qualification_profile == "correctness"
                                           and record["id"] == "m5.codegen-performance" else "passed")
                       for record in observed)
                or report["unmet_required"] != []):
            return ["report lacks the complete passing gate roster"]
        evidence = report["evidence"]
        expected_evidence = {name for record in contract["gates"] for name in record["evidence"]}
        if gate == "m5" and qualification_profile == "correctness":
            expected_evidence -= set(contract["qualification_profiles"]["correctness"]["deferred_evidence"])
        if not isinstance(evidence, Mapping) or set(evidence) != expected_evidence:
            return ["report lacks current evidence for every gate"]
        producer = importlib.import_module(gate_file.stem)
        pin = harness.load_pin()
        if gate == "m5":
            summary = producer.validate_contract(contract, pin, producer.native_test_targets())
        else:
            api = harness.read_json(harness.ALLOCATOR_ROOT / "api-v3.5.0.json")
            if gate == "m6":
                summary = producer.validate_contract(contract, api, pin)
            else:
                summary = producer.validate_contract(
                    contract, api, pin, producer.sibling_owned_items(contract["inventory"]))
        runnable_evidence = summary["runnable_evidence"]
        if gate == "m5" and qualification_profile == "correctness":
            active = producer.active_evidence(contract, qualification_profile)
            runnable_evidence = {name: command for name, command in runnable_evidence.items() if name in active}
        if set(evidence) != set(runnable_evidence):
            return ["report lacks executed producers for every gate"]
        reconstructed = (producer.gate_report(contract, summary, evidence, qualification_profile=qualification_profile)
                         if gate == "m5" and qualification_profile == "correctness"
                         else producer.gate_report(contract, summary, evidence))
        if reconstructed["overall_status"] != "passed":
            return ["report retains unresolved current gate conditions"]
        if (report.get("overall_status") != reconstructed["overall_status"]
                or report["gates"] != reconstructed["gates"]
                or report["unmet_required"] != reconstructed["unmet_required"]):
            return ["report differs from current gate classification"]
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
            canonical = runnable_evidence[name]
            if gate == "m6":
                if entry.get("runner") != canonical:
                    return [f"evidence {name} lacks its executed producer"]
            elif isinstance(canonical, Mapping):
                if entry.get("receipt") != canonical:
                    return [f"evidence {name} lacks its executed producer"]
            else:
                scratch = artifacts.resolve() / name.replace(":", "-")
                command = [argument.replace(producer.SCRATCH_PLACEHOLDER, str(scratch))
                           for argument in canonical]
                if entry.get("command") != command:
                    return [f"evidence {name} lacks its executed producer"]
            log = harness.ROOT / entry["log"]
            if log.parent.resolve() != artifacts.resolve() or log.is_symlink() or not log.is_file():
                return [f"evidence {name} lacks its retained raw log"]
            if records[name] != engine.file_record(log):
                return [f"evidence {name} differs from its retained raw log"]
            if newest is not None and log.stat().st_mtime_ns < newest:
                return [f"evidence {name} predates the newest qualified report"]
        if gate == "m4":
            stage_path = artifacts / "aligned-preservation.json"
            if stage_path.is_symlink() or not stage_path.is_file():
                return ["M4 aligned stage lacks its retained profile receipt"]
            stage = harness.read_json(stage_path)
            receipt = producer.read_operations_profiles(producer.API_PROFILES, ("operations", "api-modes"))
            if (stage.get("status") != "passed" or stage.get("scenario") != "aligned-preservation"
                    or stage.get("operation_profile_receipt") != engine.file_record(receipt.path)):
                return ["M4 aligned stage profile receipt identity differs"]
            traces = {}
            for profile in producer.API_PROFILES:
                for side in ("c", "rust"):
                    record = harness.read_json(receipt.path.parent / "logs" / f"{profile}-api-modes-{side}.json")
                    traces[f"{profile}.{side}"] = producer.parse_operations_trace(
                        str(record["stdout"]), f"{profile} {side} API trace")
            if stage.get("api_profiles") != traces:
                return ["M4 aligned stage differs from its authenticated valid profiles"]
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
    cohort = [record for record in records if not record["unmet"]]
    integrated_paths = discover_integrated() if integrated_reports is None else integrated_reports
    integrated_result = integrated_condition(integrated_paths, inspect_integrated, cohort)
    conditions = [
        matrix_condition(records),
        *report_conditions(records),
        codegen_condition(codegen_report, [record for record in records if not record["unmet"]]),
        convergence_condition(evaluate_convergence, report_paths, integrated_paths, gate_root),
        integrated_result,
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
