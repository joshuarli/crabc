#!/usr/bin/env python3
"""Compare worker attachment, reset, owner exit, and free statistics with pinned C."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path

import run as harness
import perf_engine_x86_64 as engine
import perf_integrated_x86_64 as integrated
from x86_64_m7_gate import parse_options_trace


FIXTURE = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_worker_transfer_oracle.c"
REPORT = harness.ARTIFACT_ROOT / "x86_64/m7-statistics-worker-transfer/profile.json"
BEGIN = "CRABC_MI_M7_STATISTICS_WORKER_TRANSFER_TRACE_BEGIN"
END = "CRABC_MI_M7_STATISTICS_WORKER_TRANSFER_TRACE_END"
STAGES = ("before", "first_alloc", "first_reset", "first_exit", "second_attach",
          "remote_free", "second_reset", "local_free", "second_exit")
COUNT_FIELDS = ("normal", "requested", "first_bin", "second_bin", "pages",
                "first_page_bin", "second_page_bin", "threads", "theaps")
TARGET = "x86_64-unknown-linux-musl"
ALIGNED_FIXTURE = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_aligned_transfer_driver.c"
ALIGNED_BEGIN = "CRABC_MI_M7_STATISTICS_ALIGNED_TRANSFER_TRACE_BEGIN"
ALIGNED_END = "CRABC_MI_M7_STATISTICS_ALIGNED_TRANSFER_TRACE_END"
ALIGNED_STAGES = ("before", "allocated", "refused", "owner_exit", "remote_free", "remote_exit", "collected")
ALIGNED_COUNTS = ("normal", "huge", "requested", "pages", "threads", "theaps", "reserved", "committed")
ALIGNED_PROFILES = {"stat-0": (0, False), "stat-1": (1, False),
                    "stat-2": (2, False), "debug-1": (2, True)}
ALIGNED_ARTIFACTS = REPORT.parent / "aligned-transfer"


INITIAL_BEGIN = "CRABC_MI_M7_STATISTICS_INITIAL_TRANSFER_TRACE_BEGIN"
INITIAL_END = "CRABC_MI_M7_STATISTICS_INITIAL_TRANSFER_TRACE_END"
INITIAL_STAGES = ("before", "untouched", "allocated", "owner_exit", "freed", "collected")
INITIAL_REQUESTS = {"small": (64, 0), "medium": (32768, 0),
                    "huge": (589824, 0), "os-aligned-small": (17, 1048576)}
INITIAL_ARTIFACTS = REPORT.parent / "initial-attachment"


def validate_initial(trace: dict[str, str], level: int, request: str, side: str, stderr: str = "", *, debug: bool = False) -> dict[str, str]:
    size, alignment = INITIAL_REQUESTS[request]
    expected = {"profile.level", "allocation.request", "allocation.alignment", "allocation.usable"}
    fields = (*ALIGNED_COUNTS, "malloc_bins", "page_bins", "normal_count", "huge_count")
    expected.update(f"{stage}.{field}" for stage in INITIAL_STAGES for field in fields)
    expected.update(f"{stage}.{field}.hex" for stage in ("owner_output", "final_output")
                    for field in ("binned", "huge", "requested"))
    if (set(trace) != expected or trace["profile.level"] != str(level)
            or trace["allocation.request"] != str(size) or trace["allocation.alignment"] != str(alignment)
            or int(trace["allocation.usable"]) < size):
        raise harness.HarnessError(f"{side} lost the first allocation request boundary")
    for stage in INITIAL_STAGES:
        for field in ALIGNED_COUNTS:
            count(trace, stage, field)
        for field in ("malloc_bins", "page_bins"):
            bins = set()
            for row in trace[f"{stage}.{field}"].split(";"):
                if not row:
                    continue
                values = tuple(int(word) for word in row.split(":"))
                if len(values) != 4 or values[0] in bins or values[0] < 0:
                    raise harness.HarnessError(f"{side} has invalid {stage}.{field}")
                bins.add(values[0])
        for field in ("normal_count", "huge_count"):
            int(trace[f"{stage}.{field}"])
        if level == 0 and any(count(trace, stage, field) != (0, 0, 0) for field in ("normal", "requested")):
            raise harness.HarnessError(f"{side} enabled disabled allocation statistics")
        if level == 1 and count(trace, stage, "requested") != (0, 0, 0):
            raise harness.HarnessError(f"{side} enabled level-two requested statistics")
    if any(trace[f"before.{field}"] != trace[f"untouched.{field}"] for field in fields):
        raise harness.HarnessError(f"{side} attached an untouched worker during its statistics query")
    if count(trace, "allocated", "theaps") != (1, 1, 1) or count(trace, "owner_exit", "theaps") != (1, 1, 0):
        raise harness.HarnessError(f"{side} lost first allocation attachment or owner exit")
    if level == 0:
        allocated = count(trace, "allocated", "huge")
        if request in ("huge", "os-aligned-small") and allocated[0] <= 0:
            raise harness.HarnessError(f"{side} lost unconditional huge-page allocation statistics")
        for stage in ("owner_exit", "freed", "collected"):
            if count(trace, stage, "huge") != allocated:
                raise harness.HarnessError(f"{side} charged a level-zero huge free")
    for stage in ("owner_output", "final_output"):
        for field in ("binned", "huge", "requested"):
            try:
                row = bytes.fromhex(trace[f"{stage}.{field}.hex"]).decode("ascii")
            except (ValueError, UnicodeDecodeError) as error:
                raise harness.HarnessError(f"{side} has invalid printed {stage}.{field}") from error
            label = "malloc req" if field == "requested" else field
            if row and (not row.startswith(f"  {label}") or ":" not in row):
                raise harness.HarnessError(f"{side} changed printed {stage}.{field} label")
            if level == 2 and field == "requested" and not row:
                raise harness.HarnessError(f"{side} lost printed requested total")


    accounted = dict(trace)
    if request == "os-aligned-small":
        # The cold worker's OS mapping can require a new two-level PageMap
        # submap. It retains that 64 KiB charge after the client is freed.
        # Compare source transitions only after proving the address-dependent
        # charge in each execution; leave the recorded raw counts unchanged.
        placement = {}
        for line in stderr.splitlines():
            if line.startswith("placement."):
                key, separator, value = line.partition("=")
                if not separator or key in placement:
                    raise harness.HarnessError(f"{side} has ambiguous PageMap placement")
                try:
                    placement[key] = int(value)
                except ValueError as error:
                    raise harness.HarnessError(f"{side} has invalid PageMap placement") from error
        expected_placement = {"placement.warm_index", "placement.client_index", "placement.client_lower_bound_index", "placement.client_bound_index"}
        expected_placement.update(f"placement.{stage}.mmap_calls" for stage in INITIAL_STAGES)
        if set(placement) != expected_placement or any(value < 0 for value in placement.values()):
            raise harness.HarnessError(f"{side} lost its PageMap placement witness")
        target = placement["placement.client_index"]
        if target != placement["placement.client_bound_index"] or target != placement["placement.client_lower_bound_index"]:
            raise harness.HarnessError(f"{side} spans multiple PageMap submaps")
        new_submap = int(target != placement["placement.warm_index"])
        charge = new_submap * 65536
        for stage in INITIAL_STAGES:
            active = stage not in ("before", "untouched")
            if placement[f"placement.{stage}.mmap_calls"] != (1 + new_submap if active else 0):
                raise harness.HarnessError(f"{side} lost source {stage} PageMap mapping charge")
            for field in ("reserved", "committed"):
                if not active:
                    base = (0, 0, 0)
                elif field == "reserved":
                    # The aligned OS reserve is alignment plus one 64 KiB slice.
                    base = (1114112, 1114112, 0 if stage in ("freed", "collected") else 1114112)
                elif debug:
                    # The pinned debug profile has a distinct committed
                    # total/current transition; its sampled peak delta stays
                    # lower. Keep that source profile visible independently
                    # of the address-dependent submap charge.
                    base = (196608, 131072, 131072 if stage in ("freed", "collected") else 196608)
                else:
                    base = (131072, 131072, 65536 if stage in ("freed", "collected") else 131072)
                expected_count = tuple(value + (charge if active else 0) for value in base)
                if count(trace, stage, field) != expected_count:
                    raise harness.HarnessError(f"{side} lost source {stage}.{field} PageMap charge")
                accounted[f"{stage}.{field}"] = ",".join(str(value) for value in base)
    return accounted


def validate_aligned(trace: dict[str, str], level: int, fresh: bool, side: str) -> None:
    expected = {"profile.level", "profile.fresh_free", "allocation.small_usable",
                "allocation.huge_usable", "allocation.refused"}
    expected.update(f"{stage}.{field}" for stage in ALIGNED_STAGES
                    for field in (*ALIGNED_COUNTS, "malloc_bins", "page_bins", "normal_count", "huge_count"))
    expected.update(f"{stage}.{field}.hex" for stage in ("owner_output", "freeing_output", "final_output")
                    for field in ("binned", "huge", "requested"))
    if set(trace) != expected or trace["profile.level"] != str(level) or trace["profile.fresh_free"] != str(int(fresh)):
        raise harness.HarnessError(f"{side} has an incomplete aligned transfer trace")
    if (trace["allocation.refused"] != "1" or int(trace["allocation.small_usable"]) < 33
            or int(trace["allocation.huge_usable"]) < 512 * 1024 + 1):
        raise harness.HarnessError(f"{side} lost the aligned allocation/refusal boundary")
    for stage in ALIGNED_STAGES:
        for field in ALIGNED_COUNTS:
            count(trace, stage, field)
        for field in ("malloc_bins", "page_bins"):
            bins = set()
            for row in trace[f"{stage}.{field}"].split(";"):
                if not row:
                    continue
                values = tuple(int(word) for word in row.split(":"))
                if len(values) != 4 or values[0] in bins or values[0] < 0:
                    raise harness.HarnessError(f"{side} has invalid {stage}.{field}")
                bins.add(values[0])
        for field in ("normal_count", "huge_count"):
            int(trace[f"{stage}.{field}"])
        if level == 0 and any(count(trace, stage, field) != (0, 0, 0)
                              for field in ("normal", "requested")):
            raise harness.HarnessError(f"{side} enabled disabled allocation statistics")
        if level == 1 and count(trace, stage, "requested") != (0, 0, 0):
            raise harness.HarnessError(f"{side} enabled level-two requested statistics")
    for field in (*ALIGNED_COUNTS, "malloc_bins", "page_bins", "normal_count", "huge_count"):
        if trace[f"allocated.{field}"] != trace[f"refused.{field}"]:
            raise harness.HarnessError(f"{side} charged failed aligned allocation to {field}")
    if level == 0:
        allocated = count(trace, "allocated", "huge")
        if allocated[0] <= 0 or allocated != (allocated[0], allocated[0], allocated[0]):
            raise harness.HarnessError(f"{side} lost unconditional huge-page allocation statistics")
        for stage in ALIGNED_STAGES[1:]:
            if count(trace, stage, "huge") != allocated or trace[f"{stage}.huge_count"] != "1":
                raise harness.HarnessError(f"{side} charged a level-zero free or lost its huge allocation count")
    for stage in ("owner_output", "freeing_output", "final_output"):
        for field in ("binned", "huge", "requested"):
            try:
                row = bytes.fromhex(trace[f"{stage}.{field}.hex"]).decode("ascii")
            except (ValueError, UnicodeDecodeError) as error:
                raise harness.HarnessError(f"{side} has invalid printed {stage}.{field}") from error
            label = "malloc req" if field == "requested" else field
            if row and (not row.startswith(f"  {label}") or ":" not in row):
                raise harness.HarnessError(f"{side} changed printed {stage}.{field} label")
            if level == 2 and stage in ("owner_output", "final_output") and field == "requested" and not row:
                raise harness.HarnessError(f"{side} lost printed {stage}.{field} total")


def run_worker_transfer_matrix(offline: bool, selected: str | None = None, freeing_worker: str | None = None, *, initial: bool = False, request: str | None = None, placement_diagnostic: bool = False) -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    family = "initial-attachment" if initial else "aligned-transfer"
    artifacts = INITIAL_ARTIFACTS if initial else ALIGNED_ARTIFACTS
    fixture = FIXTURE if initial else ALIGNED_FIXTURE
    begin, end = (INITIAL_BEGIN, INITIAL_END) if initial else (ALIGNED_BEGIN, ALIGNED_END)
    artifacts.mkdir(parents=True, exist_ok=True)
    profiles = {selected: ALIGNED_PROFILES[selected]} if selected else ALIGNED_PROFILES
    results = {}
    with harness.temporary_directory(f"crabc-m7-{family}-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        for profile, (level, debug) in profiles.items():
            retained = artifacts / profile
            retained.mkdir(exist_ok=True)
            flags = [f"-DMI_STAT={level}" if flag == "-DMI_STAT=0" else
                     "-DMI_DEBUG=1" if debug and flag == "-DMI_DEBUG=0" else flag
                     for flag in harness.CONFIGURATION_PROFILES["release"]
                     if not (debug and flag == "-DNDEBUG")]
            features = (["crabc-mimalloc/mi-debug-1"] if debug else
                        [f"crabc-mimalloc/mi-stat-{level}"] if level else [])
            target = retained / "cargo-target"
            build = harness.command_record([
                harness.require_tool("cargo"), "build", "--locked", "--offline", "--release",
                "--target", TARGET, "-p", "crabc-mimalloc-native-mi-adapter", "--no-default-features",
                *(["--features", ",".join(features)] if features else []), "--target-dir", str(target),
            ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=3600)
            harness.require_success(build, f"{profile} {family} adapter build")
            library = target / TARGET / "release/libcrabc_mimalloc_native_mi_adapter.a"
            archive_product = retained / library.name
            shutil.copy2(library, archive_product)
            worker_cases = ((request,) if request else tuple(INITIAL_REQUESTS)) if initial else ((freeing_worker,) if freeing_worker else ("attached", "fresh"))
            for case_name in worker_cases:
                fresh = case_name == "fresh"
                case = retained / case_name
                case.mkdir(exist_ok=True)
                common = [harness.require_tool("musl-gcc"), "-std=c11", "-ftls-model=initial-exec",
                          "-DMI_LIBC_MUSL=1", *flags, f"-DCRABC_STAT_LEVEL={level}",
                          *(["-DCRABC_INITIAL_ATTACHMENT=1", f"-DCRABC_INITIAL_REQUEST={INITIAL_REQUESTS[case_name][0]}",
                             f"-DCRABC_INITIAL_ALIGNMENT={INITIAL_REQUESTS[case_name][1]}",
                             *(["-DCRABC_INITIAL_PLACEMENT_DIAGNOSTIC=1"] if placement_diagnostic or case_name == "os-aligned-small" else [])] if initial else [f"-DCRABC_FRESH_FREE={int(fresh)}"]),
                          "-I", str(source / "include"), str(fixture)]
                builds = {}
                executions = {}
                products = {}
                for side, provider in (("c", source / "src/static.c"), ("rust", library)):
                    product = case / f"{family}-{side}"
                    builds[side] = harness.command_record([*common, str(provider), "-pthread", "-o", str(product)], cwd=source)
                    harness.require_success(builds[side], f"{profile} {side} {family} link")
                    executions[side] = harness.command_record([str(product)], cwd=case, env={}, timeout_seconds=60)
                    products[side] = engine.file_record(product)
                report = {"status": "failed", "profile": profile, "level": level, "debug": debug,
                          **({"initial_request": case_name} if initial else {"fresh_free": fresh}), "adapter_build": build, "builds": builds,
                          "executions": executions, "products": products,
                          "adapter_archive": engine.file_record(archive_product),
                          "provenance": {"pin": pin, "git": engine.git_provenance(),
                                         "image": os.environ.get("CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID"),
                                         "source_seal": integrated.source_seal(),
                                         "driver": engine.file_record(fixture),
                                         "reader": engine.file_record(Path(__file__))}}
                report_path = case / "report.json"
                harness.write_json(report_path, report)
                traces = {}
                for side, execution in executions.items():
                    harness.require_success(execution, f"{profile} {side} {family} execution")
                    traces[side] = parse_options_trace(execution["stdout"], side, begin, end)
                report["traces"] = traces
                harness.write_json(report_path, report)
                compared_traces = {}
                for side, trace in traces.items():
                    if initial:
                        compared_traces[side] = validate_initial(trace, level, case_name, side, executions[side]["stderr"], debug=debug)
                    else:
                        validate_aligned(trace, level, fresh, side)
                        compared_traces[side] = trace
                mismatch = {key: {side: traces[side][key] for side in traces}
                            for key in traces["c"] if compared_traces["c"][key] != compared_traces["rust"][key]}
                report.update(mismatch=mismatch, compared_key_count=len(traces["c"]),
                              status="failed" if mismatch else "passed")
                harness.write_json(report_path, report)
                results[f"{profile}/{case_name}"] = report["status"]
                if mismatch:
                    raise harness.HarnessError(f"{profile}/{case_name} worker statistics differ: {mismatch}")
                print(f"{profile} {case_name}: passed {len(traces['c'])} keys", flush=True)
    shutil.copy2(fixture, artifacts / fixture.name)
    harness.write_json(artifacts / "report.json", {"status": "passed", "profiles": results,
                       "provenance": {"git": engine.git_provenance(), "source_seal": integrated.source_seal()}})
    return 0


def replay_worker_transfer_matrix(root: Path, *, initial: bool = False) -> int:
    """Authenticate and execute the retained worker statistics matrix."""
    harness.require_native_x86_64()
    fixture = FIXTURE if initial else ALIGNED_FIXTURE
    begin, end = (INITIAL_BEGIN, INITIAL_END) if initial else (ALIGNED_BEGIN, ALIGNED_END)
    cases = tuple(INITIAL_REQUESTS) if initial else ("fresh", "attached")
    summary = json.loads((root / "report.json").read_text())
    expected = {f"{profile}/{worker}" for profile in ALIGNED_PROFILES for worker in cases}
    if summary.get("status") != "passed" or set(summary.get("profiles", {})) != expected:
        raise harness.HarnessError("retained worker statistics matrix is incomplete")
    compared = 0
    for profile, (level, debug) in ALIGNED_PROFILES.items():
        for worker in cases:
            case = root / profile / worker
            report = json.loads((case / "report.json").read_text())
            if (report.get("status") != "passed" or report.get("profile") != profile
                    or report.get("level") != level or report.get("debug") != debug
                    or (report.get("initial_request") if initial else report.get("fresh_free")) != (worker if initial else (worker == "fresh"))):
                raise harness.HarnessError(f"retained {profile}/{worker} has a different statistics profile")
            provenance = report["provenance"]
            if (not provenance.get("image")
                    or provenance["image"] != os.environ.get("CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID")):
                raise harness.HarnessError(f"retained {profile}/{worker} has a different or missing pinned image")
            if not provenance["git"]["clean"] or integrated.source_seal_unmet(provenance["source_seal"]):
                raise harness.HarnessError(f"retained {profile}/{worker} has a different or dirty source")
            for key, current in (("driver", fixture), ("reader", Path(__file__))):
                if source_hash(current) != provenance[key]["sha256"]:
                    raise harness.HarnessError(f"retained {profile}/{worker} changed {key}")
            archive = root / profile / Path(report["adapter_archive"]["path"]).name
            if (archive.stat().st_size != report["adapter_archive"]["bytes"]
                    or source_hash(archive) != report["adapter_archive"]["sha256"]):
                raise harness.HarnessError(f"retained {profile} changed its linked adapter archive")
            traces = {}
            for side in ("c", "rust"):
                record = report["products"][side]
                binary = case / Path(record["path"]).name
                if binary.stat().st_size != record["bytes"] or source_hash(binary) != record["sha256"]:
                    raise harness.HarnessError(f"retained {profile}/{worker}/{side} changed product bytes")
                execution = harness.command_record([str(binary.resolve())], cwd=root, env={}, timeout_seconds=60)
                harness.require_success(execution, f"retained {profile}/{worker}/{side} physical replay")
                trace = parse_options_trace(execution["stdout"], side, begin, end)
                retained_execution = report["executions"][side]
                harness.require_success(retained_execution, f"retained {profile}/{worker}/{side} original execution")
                retained_trace = parse_options_trace(retained_execution["stdout"], side, begin, end)
                if retained_trace != report["traces"][side]:
                    raise harness.HarnessError(f"retained {profile}/{worker}/{side} changed its raw trace")
                if initial:
                    retained_accounted = validate_initial(retained_trace, level, worker, side, retained_execution["stderr"], debug=debug)
                    accounted = validate_initial(trace, level, worker, side, execution["stderr"], debug=debug)
                else:
                    validate_aligned(retained_trace, level, worker == "fresh", side)
                    validate_aligned(trace, level, worker == "fresh", side)
                    retained_accounted, accounted = retained_trace, trace
                if accounted != retained_accounted:
                    raise harness.HarnessError(f"retained {profile}/{worker}/{side} changed observable statistics")
                traces[side] = accounted
            if traces["c"] != traces["rust"]:
                raise harness.HarnessError(f"retained {profile}/{worker} has a source statistics difference")
            compared += len(traces["c"])
    print(f"Worker transfer physical replay: passed {len(expected)} profiles, {compared} exact keys")
    return 0


def source_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def count(trace: dict[str, str], stage: str, field: str) -> tuple[int, int, int]:
    parts = tuple(int(part) for part in trace[f"{stage}.{field}"].split(","))
    if len(parts) != 3:
        raise harness.HarnessError(f"invalid {stage}.{field} count")
    return parts


def validate(trace: dict[str, str], side: str) -> None:
    expected = {"profile.level", "first.bin", "second.bin"}
    expected.update(f"{stage}.{field}" for stage in STAGES
                    for field in (*COUNT_FIELDS, "normal_count"))
    if set(trace) != expected or trace["profile.level"] != "2":
        raise harness.HarnessError(f"{side} has an incomplete worker transfer trace")
    if (trace["first.bin"], trace["second.bin"]) != ("8", "2"):
        raise harness.HarnessError(f"{side} did not exercise the source block bins")
    for stage in STAGES:
        for field in COUNT_FIELDS:
            count(trace, stage, field)
        int(trace[f"{stage}.normal_count"])
    # These values expose the source's live reset, negative remote debit, and
    # owner exits. The requested count intentionally remains live after free.
    anchors = {
        ("first_alloc", "normal"): (64, 64, 64),
        ("first_reset", "normal"): (64, 64, 64),
        ("first_exit", "threads"): (1, 1, 0),
        ("second_attach", "normal"): (80, 80, 80),
        ("second_attach", "pages"): (2, 2, 2),
        ("remote_free", "normal"): (80, 80, 16),
        ("remote_free", "first_bin"): (1, 1, 0),
        ("remote_free", "pages"): (2, 2, 1),
        ("second_reset", "normal"): (80, 80, 16),
        ("local_free", "normal"): (80, 80, 0),
        ("second_exit", "pages"): (2, 2, 0),
        ("second_exit", "requested"): (80, 80, 80),
        ("second_exit", "theaps"): (2, 1, 0),
    }
    for (stage, field), expected_count in anchors.items():
        if count(trace, stage, field) != expected_count:
            raise harness.HarnessError(f"{side} lost source {stage}.{field} transition")
    if trace["second_exit.normal_count"] != "2":
        raise harness.HarnessError(f"{side} lost source allocation count")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--aligned-transfer", action="store_true")
    parser.add_argument("--initial-attachment", action="store_true")
    parser.add_argument("--initial-request", choices=INITIAL_REQUESTS)
    parser.add_argument("--initial-placement-diagnostic", action="store_true",
                        help="retain live-client PageMap indices and public mapping counters in stderr")
    parser.add_argument("--read-initial-attachment", type=Path)
    parser.add_argument("--profile", choices=ALIGNED_PROFILES)
    parser.add_argument("--read-aligned-transfer", type=Path)
    parser.add_argument("--freeing-worker", choices=("attached", "fresh"))
    args = parser.parse_args()
    if args.initial_placement_diagnostic and not args.initial_attachment:
        parser.error("--initial-placement-diagnostic requires --initial-attachment")
    if args.initial_request is not None and not args.initial_attachment:
        parser.error("--initial-request requires --initial-attachment")
    if args.read_initial_attachment is not None:
        if args.initial_attachment or args.aligned_transfer or args.profile or args.freeing_worker or args.read_aligned_transfer:
            parser.error("physical initial attachment replay cannot produce a matrix")
        return replay_worker_transfer_matrix(args.read_initial_attachment, initial=True)
    if args.initial_attachment:
        if args.aligned_transfer or args.freeing_worker or args.read_aligned_transfer:
            parser.error("initial attachment is a separate worker lifecycle")
        return run_worker_transfer_matrix(args.offline, args.profile, initial=True, request=args.initial_request, placement_diagnostic=args.initial_placement_diagnostic)
    if args.read_aligned_transfer is not None:
        if args.aligned_transfer or args.profile is not None or args.freeing_worker is not None:
            parser.error("--read-aligned-transfer cannot produce a new matrix")
        return replay_worker_transfer_matrix(args.read_aligned_transfer)
    if args.aligned_transfer:
        return run_worker_transfer_matrix(args.offline, args.profile, args.freeing_worker)
    if args.profile is not None or args.freeing_worker is not None:
        parser.error("--profile and --freeing-worker require --aligned-transfer")
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, args.offline)
    cc = harness.require_tool("musl-gcc")
    cargo = harness.require_tool("cargo")
    with harness.temporary_directory("crabc-m7-statistics-worker-transfer-") as temp_name:
        temp = Path(temp_name)
        source = harness.safe_extract(archive, temp / "source", pin["archive_root"])
        flags = ["-DMI_STAT=2" if flag == "-DMI_STAT=0" else flag
                 for flag in harness.CONFIGURATION_PROFILES["release"]]
        common = [cc, "-std=c11", "-O2", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                  *flags, "-I", str(source / "include"), str(FIXTURE)]
        c_driver = temp / "worker-transfer-c"
        c_build = harness.command_record([*common, str(source / "src/static.c"),
                                          "-pthread", "-o", str(c_driver)], cwd=source)
        harness.require_success(c_build, "pinned worker transfer build")
        target_dir = temp / "cargo-target"
        rust_build = harness.command_record([
            cargo, "build", "--locked", "--offline", "--release", "--target", TARGET,
            "-p", "crabc-mimalloc-native-mi-adapter", "--no-default-features",
            "--features", "crabc-mimalloc/mi-stat-2", "--target-dir", str(target_dir),
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=3600)
        harness.require_success(rust_build, "native worker transfer adapter build")
        rust_driver = temp / "worker-transfer-rust"
        library = target_dir / TARGET / "release" / "libcrabc_mimalloc_native_mi_adapter.a"
        rust_link = harness.command_record([*common, str(library), "-pthread", "-o", str(rust_driver)],
                                           cwd=source)
        harness.require_success(rust_link, "native worker transfer driver link")
        traces = {}
        executions = {}
        for side, driver in (("c", c_driver), ("rust", rust_driver)):
            execution = harness.command_record([str(driver)], cwd=source, env={}, timeout_seconds=60)
            harness.require_success(execution, f"{side} worker transfer execution")
            trace = parse_options_trace(str(execution["stdout"]), side, BEGIN, END)
            validate(trace, side)
            traces[side] = trace
            executions[side] = execution
        mismatch = sorted(key for key in traces["c"] if traces["c"][key] != traces["rust"][key])
        report = {
            "status": "red" if mismatch else "passed",
            "git": engine.git_provenance(),
            "pin": {key: pin[key] for key in ("revision", "sha256", "tag")},
            "source_files": harness.source_file_records(source, (
                "include/mimalloc-stats.h", "src/stats.c", "src/init.c", "src/heap.c",
                "src/theap.c", "src/alloc.c", "src/free.c", "src/page.c", "src/static.c")),
            "fixture_sha256": source_hash(FIXTURE),
            "reader_sha256": source_hash(Path(__file__)),
            "rust_source_sha256": {
                path: source_hash(harness.ROOT / path)
                for path in ("crabc-mimalloc/src/statistics.rs",
                             "crabc-mimalloc/src/runtime_lifecycle.rs",
                             "crabc-mimalloc/src/subproc_main_heaps.rs",
                             "crabc-mimalloc/src/single_thread.rs",
                             "compat/allocator/native-mi-adapter/src/lib.rs")
            },
            "c_build_command": c_build["command"],
            "rust_build_command": rust_build["command"],
            "rust_link_command": rust_link["command"],
            "executions": executions,
            "traces": traces,
            "mismatch_keys": mismatch,
        }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    harness.write_json(REPORT, report)
    print(f"worker transfer statistics: {report['status']} ({len(mismatch)} differing keys)")
    print(f"report: {harness.relative(REPORT)}")
    return 1 if mismatch else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}")
        raise SystemExit(2)
