#!/usr/bin/env python3
"""Allocator C/Rust comparison through the installed static and dynamic products.

plan.md's final allocator comparison uses "equivalent opaque C/Rust
boundaries and fully integrated products". The engine matrix
(``perf_engine_x86_64.py``) covers the first; this runner covers the second.
It builds four installed products with their own builders:

* ``scripts/build_x86_64_owned_sysroot.py`` (static) and
  ``scripts/build_x86_64_owned_dynamic_sysroot.py`` (dynamic),
* each with ``--allocator-backend pinned-c-evidence`` (lane ``pinned_c``:
  the accepted C wrapper over exact pinned mimalloc v3.5.0, an evidence-only
  product) and ``--allocator-backend native-shadow`` (lane ``rust_engine``).

The engine fixture and ``perf-x86_64/integrated-libc-backend.c`` (every
operation is the public libc entry point) are compiled once per link mode by
the installed drivers; the objects must be byte-identical across the two
backends. Dynamic programs run chrooted into a copy of their product so
their interpreter and libc resolve there.

Rows are a critical subset of the engine matrix (``integrated-matrix``
manifest) in each link mode, with the engine's statistics (throughput, slow
batch p99, exec-image peak RSS, peak-state PSS), plus one
startup-plus-first-allocation row timed by a harness launcher. The report
records the engine's uncontended-host evidence.

``validate_integrated_report`` rereads a report and names every unmet
condition. The C reference must be the evidence product whose recorded
``MI_MALLOC_VERSION`` is 30500 and whose upstream identity is the pin.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
ALLOCATOR_ROOT = ROOT / "compat/allocator"
FIXTURE_ROOT = ALLOCATOR_ROOT / "perf-x86_64"
MANIFEST = FIXTURE_ROOT / "integrated-matrix-v3.5.0.json"
LIBC_BACKEND = FIXTURE_ROOT / "integrated-libc-backend.c"
LAUNCHER = FIXTURE_ROOT / "integrated-startup-launcher.c"
KIND = "crabc-mimalloc-x86_64-integrated-performance"
SCHEMA = 1
# Every tracked input of the installed products and of this measurement.
SEALED_PATHS = (
    "Cargo.lock", "Cargo.toml", "rust-toolchain.toml", "libc", "ldso", "crt", "builtins", "crabc-core",
    "crabc-mimalloc", "include", "scripts", "compat/x86_64", "compat/allocator/perf-x86_64",
    "compat/allocator/perf_engine_x86_64.py", "compat/allocator/perf_x86_64.py",
    "compat/allocator/perf_integrated_x86_64.py",
)
REFERENCE_BACKEND = "pinned-c-evidence"
REFERENCE_MI_MALLOC_VERSION = 30500


def _load_engine():
    name = "perf_engine_x86_64"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ALLOCATOR_ROOT / "perf_engine_x86_64.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


engine = _load_engine()
HarnessError = engine.HarnessError
REPORT_ROOT = engine.REPORT_ROOT.parent / "perf-integrated"
WORK_ROOT = ROOT / ".work/allocator-x86_64/integrated"


# ---- manifest ---------------------------------------------------------------


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HarnessError(f"cannot read the integrated matrix: {error}") from error
    if manifest.get("schema") != "crabc-mimalloc-x86_64-integrated-performance-matrix" or manifest.get("format") != 1:
        raise HarnessError("integrated matrix schema changed")
    if set(manifest.get("products", {})) != {"static", "dynamic"}:
        raise HarnessError("integrated matrix must name the static and dynamic products")
    if manifest.get("backends") != {"pinned_c": REFERENCE_BACKEND, "rust_engine": "native-shadow"}:
        raise HarnessError(f"integrated matrix must compare {REFERENCE_BACKEND} with native-shadow")
    engine_rows = {row["name"]: row for row in engine.load_manifest()["rows"]}
    names = manifest.get("engine_rows")
    if not isinstance(names, list) or not names or len(set(names)) != len(names):
        raise HarnessError("integrated matrix lacks its engine rows")
    for name in names:
        if name not in engine_rows or "matrix" not in engine_rows[name]["sets"]:
            raise HarnessError(f"integrated row {name} is not an engine matrix row")
    startup = manifest.get("startup_row", {})
    for key in ("launches_per_batch", "batches"):
        if type(startup.get(key)) is not int or startup[key] < 1:
            raise HarnessError(f"integrated startup row {key} is invalid")
    return manifest


def engine_rows(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = {row["name"]: row for row in engine.load_manifest()["rows"]}
    return [dict(rows[name]) for name in manifest["engine_rows"]]


def row_names(manifest: Mapping[str, Any]) -> list[str]:
    names = [*manifest["engine_rows"], manifest["startup_row"]["name"]]
    return [f"{product}/{name}" for product in ("static", "dynamic") for name in names]


# ---- source seal -------------------------------------------------------------


def _git(*arguments: str) -> str:
    completed = subprocess.run(["git", "-C", str(ROOT), *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, check=False)
    if completed.returncode != 0:
        raise HarnessError(f"git {' '.join(arguments)} failed: {completed.stderr.strip()}")
    return completed.stdout


def source_seal() -> dict[str, Any]:
    """Git object ids of every sealed path at HEAD, and whether any is dirty."""

    trees = {path: _git("rev-parse", f"HEAD:{path}").strip() for path in SEALED_PATHS}
    dirty = sorted(line for line in _git("status", "--porcelain=v1", "--", *SEALED_PATHS).splitlines() if line.strip())
    return {"objects": trees, "dirty_paths": dirty}


def source_seal_unmet(recorded: Mapping[str, Any]) -> list[str]:
    current = source_seal()
    unmet = []
    if recorded.get("dirty_paths"):
        unmet.append(f"measured sources were dirty: {recorded['dirty_paths'][:5]}")
    if current["dirty_paths"]:
        unmet.append(f"this checkout's sealed paths are dirty: {current['dirty_paths'][:5]}")
    for path, identity in current["objects"].items():
        if recorded.get("objects", {}).get(path) != identity:
            unmet.append(f"source seal: {path} differs from this checkout")
    return unmet


# ---- products ---------------------------------------------------------------


def run_logged(command: Sequence[str], log: Path, *, cwd: Path = ROOT) -> None:
    completed = subprocess.run([str(item) for item in command], cwd=cwd, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, check=False)
    log.write_bytes(completed.stdout)
    if completed.returncode != 0:
        raise HarnessError(f"command failed ({completed.returncode}): {' '.join(map(str, command))}; see {log}")


def product_backend(product: Path) -> object:
    """The static manifest names its backend; the dynamic product records it in its libc provenance."""

    selected = json.loads((product / "share/crabc/manifest.json").read_text(encoding="utf-8")).get("allocator_backend")
    shared = product / "share/crabc/libc-shared.provenance.json"
    if selected is None and shared.is_file():
        selected = json.loads(shared.read_text(encoding="utf-8")).get("allocator_backend")
    return selected


def build_products(manifest: Mapping[str, Any], work: Path, *, reuse: bool) -> dict[str, dict[str, Path]]:
    products: dict[str, dict[str, Path]] = {}
    for kind, product in manifest["products"].items():
        products[kind] = {}
        for lane, backend in manifest["backends"].items():
            output = work / "products" / f"{kind}-{backend}"
            if not (reuse and (output / "share/crabc/manifest.json").is_file()):
                output.parent.mkdir(parents=True, exist_ok=True)
                run_logged(["python3", product["builder"], "--output", output, "--allocator-backend", backend],
                           work / f"build-{kind}-{backend}.log")
            if product_backend(output) != backend:
                raise HarnessError(f"{output} is not a {backend} product")
            products[kind][lane] = output
    return products


def c_reference(products: Mapping[str, Mapping[str, Path]]) -> dict[str, Any]:
    """The evidence product's pinned mimalloc object record, identical for both link modes."""

    records = []
    for kind in products:
        root = products[kind]["pinned_c"] / "share/crabc"
        shared = root / "libc-shared.provenance.json"
        if shared.is_file():
            record = json.loads(shared.read_text(encoding="utf-8")).get("pinned_c_evidence")
        else:
            record = json.loads((root / "libc-static.provenance.json").read_text(encoding="utf-8")).get(
                "allocator_backend", {}).get("pinned_c_evidence")
        if not isinstance(record, Mapping):
            raise HarnessError(f"{kind} C reference product records no pinned-c-evidence object")
        records.append({key: record.get(key) for key in ("upstream", "mi_malloc_version", "member_sha256",
                                                          "flag_reconstruction")})
    if any(record != records[0] for record in records):
        raise HarnessError("static and dynamic C reference products carry different pinned mimalloc objects")
    return {"backend": REFERENCE_BACKEND, **records[0]}


def build_programs(manifest: Mapping[str, Any], products: Mapping[str, Mapping[str, Path]], work: Path) -> dict[str, Any]:
    """Compile the shared sources once per link mode and link them through each product."""

    source = work / "src"
    shutil.rmtree(source, ignore_errors=True)
    source.mkdir(parents=True)
    for path in (engine.FIXTURE, engine.HEADER, LIBC_BACKEND):
        shutil.copy2(path, source / path.name)
    binaries: dict[str, dict[str, Any]] = {}
    records: dict[str, Any] = {}
    for kind, product in manifest["products"].items():
        binaries[kind] = {}
        objects: dict[str, dict[str, str]] = {}
        for lane, root in products[kind].items():
            driver = root / product["driver"]
            lane_work = work / "programs" / f"{kind}-{lane}"
            shutil.rmtree(lane_work, ignore_errors=True)
            lane_work.mkdir(parents=True)
            built = []
            for name in ("engine-fixture", "integrated-libc-backend"):
                output = lane_work / f"{name}.o"
                run_logged([driver, *product["mode_flags"], *manifest["compile_flags"], "-c", source / f"{name}.c",
                            "-o", output], lane_work / f"compile-{name}.log", cwd=source)
                built.append(output)
            objects[lane] = {path.name: engine.sha256_file(path) for path in built}
            executable = lane_work / "program"
            run_logged([driver, *product["mode_flags"], *built, "-o", executable], lane_work / "link.log", cwd=source)
            if product["chroot"]:
                runtime = lane_work / "root"
                shutil.copytree(root, runtime, symlinks=True)
                shutil.copy2(executable, runtime / "program")
                binaries[kind][lane] = (runtime, "/program")
            else:
                binaries[kind][lane] = executable
            records[f"{kind}/{lane}"] = {"executable": engine.artifact_record(executable), "objects": objects[lane]}
        if objects["pinned_c"] != objects["rust_engine"]:
            raise HarnessError(f"{kind} objects differ between backends; the programs are not source- and build-identical")
    launcher = work / "programs" / "integrated-startup-launcher"
    run_logged(["musl-gcc", "-std=c11", "-O2", "-fno-pie", "-static", "-no-pie", LAUNCHER, "-o", launcher], work / "launcher.log")
    records["launcher"] = engine.artifact_record(launcher)
    return {"binaries": binaries, "launcher": launcher, "records": records}


# ---- startup row --------------------------------------------------------------


def run_startup_sample(
    program: Any, launcher: Path, startup: Mapping[str, Any], *, cpus: Sequence[int], timeout: float,
    scratch: Path, sample_name: str,
) -> dict[str, Any]:
    """Launched-process batches, plus one traced launch for exit peak RSS and peak-state PSS."""

    root, path = (program if isinstance(program, tuple) else ("-", str(program)))
    arguments = [f"batches={startup['batches']}", f"launches={startup['launches_per_batch']}", f"root={root}",
                 path, *startup["program_arguments"]]
    stdout_path, stderr_path = scratch / f"{sample_name}.stdout", scratch / f"{sample_name}.stderr"
    started = engine.time.monotonic_ns()
    pid = engine.spawn(launcher, arguments, cpus=cpus, stdout_path=stdout_path, stderr_path=stderr_path)
    launcher_process, stdout = engine.finish_process(pid, started, timeout, stdout_path, stderr_path)
    batches = engine.parse_timed_output(stdout, expected_batches=startup["batches"])
    workload, *parameters = startup["program_arguments"]
    memory_row = {"workload": workload, "params": {key: int(value) for key, value in
                                                   (item.split("=", 1) for item in parameters)}}
    memory = engine.run_timed_sample(program, memory_row, batch_divisor=1, cpus=cpus, timeout=timeout,
                                     scratch=scratch, sample_name=f"{sample_name}-memory")
    return {"arguments": arguments, "cpus": list(cpus), "batches": batches, "launcher_process": launcher_process,
            "process": memory["process"], "peak_state": memory["peak_state"]}


def measure_startup(
    binaries: Mapping[str, Any], launcher: Path, startup: Mapping[str, Any], *, mode: Mapping[str, Any],
    cpu_pool: Sequence[int] | None, timeout: float, scratch: Path, seed: int,
) -> dict[str, Any]:
    cpus = engine.choose_cpus(cpu_pool, 1)
    entry: dict[str, Any] = {"workload": "startup_first_alloc", "params": dict(startup), "cpus": cpus, "seed": seed}
    by_lane: dict[str, list[Any]] = {lane: [None] * mode["samples"] for lane in engine.LANES}
    plan = engine.paired_plan(mode["samples"], seed=seed)
    lane = engine.LANES[0]
    try:
        for lane in engine.LANES:
            for warmup in range(mode["warmup_processes"]):
                run_startup_sample(binaries[lane], launcher, startup, cpus=cpus, timeout=timeout, scratch=scratch,
                                   sample_name=f"startup-{lane}-w{warmup}")
        for lane, index in plan:
            sample = run_startup_sample(binaries[lane], launcher, startup, cpus=cpus, timeout=timeout,
                                        scratch=scratch, sample_name=f"startup-{lane}-{index}")
            sample["sample_index"] = index
            by_lane[lane][index] = sample
    except HarnessError as error:
        entry.update(status="failed", failed_lane=lane, reason=str(error))
        return entry
    entry["sample_plan"] = [{"lane": lane, "sample_index": index} for lane, index in plan]
    entry["lanes"] = {lane: {"samples": by_lane[lane]} for lane in engine.LANES}
    entry["comparison"] = engine.throughput_comparison(by_lane["pinned_c"], by_lane["rust_engine"], seed=seed)
    entry["status"] = "measured"
    return entry


# ---- driver -------------------------------------------------------------------


def run(arguments: argparse.Namespace) -> Path:
    provenance_native = engine.shared.require_native_x86_64()
    manifest = load_manifest()
    mode_name = "full" if arguments.full else "smoke"
    mode = engine.load_manifest()["modes"][mode_name]
    label = engine.validate_label(arguments.label)
    work = WORK_ROOT / label
    if not arguments.reuse_products:
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    rows = engine_rows(manifest)
    widest = max(engine.row_thread_count(row) for row in rows)
    measurement_cpus = engine.choose_cpus(arguments.cpus, widest)
    report: dict[str, Any] = {
        "schema": SCHEMA, "kind": KIND, "label": label, "mode": mode_name, "status": "pending",
        "native_execution_provenance": provenance_native,
        "lane_meaning": {lane: f"installed products with --allocator-backend {backend}"
                         for lane, backend in manifest["backends"].items()},
        "provenance": {"seal": source_seal(), "git": engine.git_provenance(),
                       "host": engine.host_provenance(measurement_cpus), "tools": engine.tool_versions(),
                       "manifest": engine.file_record(MANIFEST)},
        "products_reused": bool(arguments.reuse_products),
    }
    products = build_products(manifest, work, reuse=arguments.reuse_products)
    report["products"] = {kind: {lane: {"path": engine.shared.relative(path),
                                        "manifest": engine.file_record(path / "share/crabc/manifest.json")}
                                 for lane, path in lanes.items()} for kind, lanes in products.items()}
    report["c_reference"] = c_reference(products)
    programs = build_programs(manifest, products, work)
    report["programs"] = programs["records"]
    with tempfile.TemporaryDirectory(prefix="crabc-integrated-perf-", dir=work) as temporary:
        scratch = Path(temporary)
        host_evidence = engine.host_record_start(measurement_cpus)
        seed = 0x494E_5445_4752
        report["rows"] = {}
        for product_index, kind in enumerate(("static", "dynamic")):
            # Row names become scratch file names, so the link mode joins with "-" there.
            measured = engine.measure_rows(
                [dict(row, name=f"{kind}-{row['name']}") for row in rows], programs["binaries"][kind], memory=False,
                mode=mode, cpu_pool=arguments.cpus, timeout=arguments.timeout, scratch=scratch,
                seed=seed + 7919 * product_index, host_evidence=host_evidence, peak_hook=True)
            report["rows"].update({f"{kind}/{name.removeprefix(kind + '-')}": entry for name, entry in measured.items()})
            name = f"{kind}/{manifest['startup_row']['name']}"
            host_evidence["windows"].append(engine.contention_window(f"row:{name}", engine.CONTENTION_ROW_WINDOW_SECONDS))
            report["rows"][name] = measure_startup(
                programs["binaries"][kind], programs["launcher"], manifest["startup_row"], mode=mode,
                cpu_pool=arguments.cpus, timeout=arguments.timeout, scratch=scratch, seed=seed + 104729 + product_index)
            print(f"measured {name}", file=sys.stderr, flush=True)
        report["uncontended_host"] = engine.uncontended_host_record(engine.host_record_finish(host_evidence))
    failed = sorted(name for name, row in report["rows"].items() if row["status"] != "measured")
    report["failed_rows"] = failed
    report["status"] = "failed-rows" if failed else "ok"
    report["qualification"] = {"unmet": integrated_unmet(report, manifest)}
    path = REPORT_ROOT / f"{label}.json"
    engine.atomic_write_json(path, report)
    if failed:
        raise HarnessError(f"rows failed: {', '.join(failed)}; raw failures are recorded in {path}")
    return path


# ---- reader ---------------------------------------------------------------------


def integrated_unmet(report: Mapping[str, Any], manifest: Mapping[str, Any] | None = None) -> list[str]:
    """Every reason one integrated report is not a qualified integrated comparison."""

    manifest = load_manifest() if manifest is None else manifest
    if report.get("schema") != SCHEMA or report.get("kind") != KIND:
        return [f"report is not a schema-{SCHEMA} {KIND} report"]
    unmet: list[str] = []
    if report.get("mode") != "full":
        unmet.append(f"report is --{report.get('mode')}, not --full")
    if report.get("status") != "ok" or report.get("failed_rows"):
        unmet.append(f"report status is {report.get('status')} with failed rows {report.get('failed_rows')}")
    if report.get("products_reused"):
        unmet.append("report measured products it did not build (--reuse-products)")
    if report.get("native_execution_provenance", {}).get("execution_mode") != "native":
        unmet.append("report lacks native x86-64 execution provenance")
    unmet.extend(source_seal_unmet(report.get("provenance", {}).get("seal", {})))
    reference = report.get("c_reference", {})
    pin = engine.shared.load_pin()
    upstream = reference.get("upstream") or {}
    if (reference.get("backend") != REFERENCE_BACKEND or reference.get("mi_malloc_version") != REFERENCE_MI_MALLOC_VERSION
            or {key: upstream.get(key) for key in ("version", "revision")} != {key: pin[key] for key in ("version", "revision")}
            or upstream.get("archive_sha256") != pin["sha256"]):
        unmet.append(f"the C reference is {reference.get('backend')} with MI_MALLOC_VERSION "
                     f"{reference.get('mi_malloc_version')} and upstream {upstream.get('version')}, not the "
                     f"{REFERENCE_BACKEND} product over exact v{pin['version']} ({REFERENCE_MI_MALLOC_VERSION})")
    mode = engine.load_manifest()["modes"]["full"]
    rows = {row["name"]: row for row in engine_rows(manifest)}
    for name in row_names(manifest):
        entry = report.get("rows", {}).get(name)
        base = name.split("/", 1)[1]
        if not isinstance(entry, Mapping) or entry.get("status") != "measured":
            status = entry.get("status") if isinstance(entry, Mapping) else "absent"
            unmet.append(f"row {name} is {status}")
            continue
        c_samples, rust_samples = entry["lanes"]["pinned_c"]["samples"], entry["lanes"]["rust_engine"]["samples"]
        if report.get("mode") == "full" and (len(c_samples) != mode["samples"] or len(rust_samples) != mode["samples"]):
            unmet.append(f"row {name} lacks the full mode's {mode['samples']} samples per lane")
            continue
        if base in rows and (entry.get("workload") != rows[base]["workload"] or entry.get("params") != rows[base]["params"]):
            unmet.append(f"row {name} does not measure the engine row's workload and parameters")
        if any(engine.sample_peak_pss_kib(sample) is None for sample in (*c_samples, *rust_samples)):
            unmet.append(f"row {name} samples lack peak-state PSS")
            continue
        seed = entry.get("seed", entry.get("comparison", {}).get("bootstrap", {}).get("seed"))
        if engine.throughput_comparison(c_samples, rust_samples, seed=seed) != entry.get("comparison"):
            unmet.append(f"row {name} comparison differs from a recomputation of its raw samples")
    record = report.get("uncontended_host")
    if not isinstance(record, Mapping) or not isinstance(record.get("evidence"), Mapping):
        unmet.append("report has no uncontended_host record with raw evidence")
    else:
        reasons = engine.classify_host(record["evidence"])
        if record.get("status") != ("contended" if reasons else "uncontended") or record.get("reasons") != reasons:
            unmet.append("uncontended_host classification differs from a reclassification of its raw evidence")
        unmet.extend(f"host is not uncontended: {reason}" for reason in reasons)
    return unmet


def integrated_metrics(report: Mapping[str, Any]) -> dict[str, Any]:
    """Per-row Rust/C bounds in the promotion table's directions."""

    metrics = {}
    for name, entry in sorted(report.get("rows", {}).items()):
        if entry.get("status") != "measured":
            continue
        comparison = entry["comparison"]
        pss = comparison.get("peak_pss_kib") or {}
        metrics[name] = {
            "throughput_lower_95": comparison["throughput_ratio_rust_over_c"]["bootstrap_5th_percentile"],
            "p99_upper_95": comparison["batch_p99_ns_per_op"]["ratio_rust_over_c"]["bootstrap_95th_percentile"],
            "peak_rss_upper_95": comparison["peak_rss_kib"]["ratio_rust_over_c"]["bootstrap_95th_percentile"],
            "peak_pss_upper_95": pss.get("ratio_rust_over_c", {}).get("bootstrap_95th_percentile"),
        }
    return metrics


def inspect_integrated_report(root: Path, path: Path) -> dict[str, Any]:
    if Path(root).resolve() != ROOT.resolve():
        raise HarnessError(f"integrated reports must be read by the checkout that owns this reader: {root}")
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"unmet": [f"report is unreadable: {error}"], "metrics": None}
    try:
        return {"unmet": integrated_unmet(report), "metrics": integrated_metrics(report)}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, HarnessError) as error:
        return {"unmet": [f"report is malformed: {type(error).__name__}: {error}"], "metrics": None}


def validate_integrated_report(root: Path, path: Path) -> dict[str, Any]:
    inspected = inspect_integrated_report(root, path)
    if inspected["unmet"]:
        raise HarnessError(f"{path} is not a qualified integrated report: " + "; ".join(inspected["unmet"]))
    return {"metrics": inspected["metrics"]}


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--smoke", action="store_true", help="the engine's smoke schedule (default)")
    mode.add_argument("--full", action="store_true", help="the engine's full schedule")
    parser.add_argument("--label", default="integrated")
    parser.add_argument("--cpus", default=None, help="comma-separated allowed CPUs to use, in order")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--reuse-products", action="store_true",
                        help="reuse this label's installed products (development only; never qualifies)")
    arguments = parser.parse_args(argv)
    engine.validate_label(arguments.label)
    if arguments.cpus is not None:
        arguments.cpus = [int(item) for item in arguments.cpus.split(",") if item]
    return arguments


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        path = run(arguments)
    except (HarnessError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
