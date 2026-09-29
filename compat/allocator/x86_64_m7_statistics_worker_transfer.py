#!/usr/bin/env python3
"""Compare reset, owner exit, and cross-thread free statistics with pinned C."""

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


def run_aligned_transfer(offline: bool, selected: str | None = None, freeing_worker: str | None = None) -> int:
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, offline)
    ALIGNED_ARTIFACTS.mkdir(parents=True, exist_ok=True)
    profiles = {selected: ALIGNED_PROFILES[selected]} if selected else ALIGNED_PROFILES
    results = {}
    with harness.temporary_directory("crabc-m7-aligned-transfer-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        for profile, (level, debug) in profiles.items():
            retained = ALIGNED_ARTIFACTS / profile
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
            harness.require_success(build, f"{profile} aligned transfer adapter build")
            library = target / TARGET / "release/libcrabc_mimalloc_native_mi_adapter.a"
            archive_product = retained / library.name
            shutil.copy2(library, archive_product)
            worker_cases = (freeing_worker == "fresh",) if freeing_worker else (False, True)
            for fresh in worker_cases:
                case = retained / ("fresh" if fresh else "attached")
                case.mkdir(exist_ok=True)
                common = [harness.require_tool("musl-gcc"), "-std=c11", "-ftls-model=initial-exec",
                          "-DMI_LIBC_MUSL=1", *flags, f"-DCRABC_STAT_LEVEL={level}",
                          f"-DCRABC_FRESH_FREE={int(fresh)}", "-I", str(source / "include"), str(ALIGNED_FIXTURE)]
                builds = {}
                executions = {}
                products = {}
                for side, provider in (("c", source / "src/static.c"), ("rust", library)):
                    product = case / f"aligned-transfer-{side}"
                    builds[side] = harness.command_record([*common, str(provider), "-pthread", "-o", str(product)], cwd=source)
                    harness.require_success(builds[side], f"{profile} {side} aligned transfer link")
                    executions[side] = harness.command_record([str(product)], cwd=case, env={}, timeout_seconds=60)
                    products[side] = engine.file_record(product)
                report = {"status": "failed", "profile": profile, "level": level, "debug": debug,
                          "fresh_free": fresh, "adapter_build": build, "builds": builds,
                          "executions": executions, "products": products,
                          "adapter_archive": engine.file_record(archive_product),
                          "provenance": {"pin": pin, "git": engine.git_provenance(),
                                         "image": os.environ.get("CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID"),
                                         "source_seal": integrated.source_seal(),
                                         "driver": engine.file_record(ALIGNED_FIXTURE),
                                         "reader": engine.file_record(Path(__file__))}}
                report_path = case / "report.json"
                harness.write_json(report_path, report)
                traces = {}
                for side, execution in executions.items():
                    harness.require_success(execution, f"{profile} {side} aligned transfer execution")
                    traces[side] = parse_options_trace(execution["stdout"], side, ALIGNED_BEGIN, ALIGNED_END)
                report["traces"] = traces
                harness.write_json(report_path, report)
                mismatch = {key: {side: traces[side][key] for side in traces}
                            for key in traces["c"] if traces["c"][key] != traces["rust"][key]}
                report.update(mismatch=mismatch, compared_key_count=len(traces["c"]),
                              status="failed" if mismatch else "passed")
                harness.write_json(report_path, report)
                for side, trace in traces.items():
                    validate_aligned(trace, level, fresh, side)
                results[f"{profile}/{'fresh' if fresh else 'attached'}"] = report["status"]
                if mismatch:
                    raise harness.HarnessError(f"{profile} aligned worker transfer differs: {mismatch}")
                print(f"{profile} {'fresh' if fresh else 'attached'}: passed {len(traces['c'])} keys", flush=True)
    shutil.copy2(ALIGNED_FIXTURE, ALIGNED_ARTIFACTS / ALIGNED_FIXTURE.name)
    harness.write_json(ALIGNED_ARTIFACTS / "report.json", {"status": "passed", "profiles": results,
                       "provenance": {"git": engine.git_provenance(), "source_seal": integrated.source_seal()}})
    return 0


def replay_aligned_transfer(root: Path) -> int:
    """Authenticate and execute the complete retained aligned-owner matrix."""
    harness.require_native_x86_64()
    summary = json.loads((root / "report.json").read_text())
    expected = {f"{profile}/{worker}" for profile in ALIGNED_PROFILES for worker in ("fresh", "attached")}
    if summary.get("status") != "passed" or set(summary.get("profiles", {})) != expected:
        raise harness.HarnessError("retained aligned transfer matrix is incomplete")
    compared = 0
    for profile, (level, debug) in ALIGNED_PROFILES.items():
        for worker in ("fresh", "attached"):
            case = root / profile / worker
            report = json.loads((case / "report.json").read_text())
            if (report.get("status") != "passed" or report.get("profile") != profile
                    or report.get("level") != level or report.get("debug") != debug
                    or report.get("fresh_free") != (worker == "fresh")):
                raise harness.HarnessError(f"retained {profile}/{worker} has a different statistics profile")
            provenance = report["provenance"]
            if (not provenance.get("image")
                    or provenance["image"] != os.environ.get("CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID")):
                raise harness.HarnessError(f"retained {profile}/{worker} has a different or missing pinned image")
            if not provenance["git"]["clean"] or integrated.source_seal_unmet(provenance["source_seal"]):
                raise harness.HarnessError(f"retained {profile}/{worker} has a different or dirty source")
            for key, current in (("driver", ALIGNED_FIXTURE), ("reader", Path(__file__))):
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
                trace = parse_options_trace(execution["stdout"], side, ALIGNED_BEGIN, ALIGNED_END)
                validate_aligned(trace, level, worker == "fresh", side)
                if trace != report["traces"][side]:
                    raise harness.HarnessError(f"retained {profile}/{worker}/{side} changed observable statistics")
                traces[side] = trace
            if traces["c"] != traces["rust"]:
                raise harness.HarnessError(f"retained {profile}/{worker} has a source statistics difference")
            compared += len(traces["c"])
    print(f"Aligned transfer physical replay: passed {len(expected)} profiles, {compared} exact keys")
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
    parser.add_argument("--profile", choices=ALIGNED_PROFILES)
    parser.add_argument("--read-aligned-transfer", type=Path)
    parser.add_argument("--freeing-worker", choices=("attached", "fresh"))
    args = parser.parse_args()
    if args.read_aligned_transfer is not None:
        if args.aligned_transfer or args.profile is not None or args.freeing_worker is not None:
            parser.error("--read-aligned-transfer cannot produce a new matrix")
        return replay_aligned_transfer(args.read_aligned_transfer)
    if args.aligned_transfer:
        return run_aligned_transfer(args.offline, args.profile, args.freeing_worker)
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
