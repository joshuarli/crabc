#!/usr/bin/env python3
"""Compare the public statistics around one failed regular-page commit and retry."""

from __future__ import annotations

import argparse
import json
import shutil
import os
import sys
from pathlib import Path

import run as harness
import x86_64_m7_gate as m7
import x86_64_foundation_gate_receipts as receipts


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_page_extension_fault_driver.c"
TEST = "page::tests::failed_second_regular_extension_commit_retries_same_page_statistics"
BEGIN = "CRABC_MI_M7_STATISTICS_PAGE_EXTENSION_FAULT_TRACE_BEGIN"
END = "CRABC_MI_M7_STATISTICS_PAGE_EXTENSION_FAULT_TRACE_END"
REPORT = m7.ARTIFACTS / "statistics-page-extension-fault.json"
TARGET = "x86_64-unknown-linux-musl"


PROFILES = {"stat-0": (0, False), "stat-1": (1, False),
            "stat-2": (2, False), "debug-1": (2, True), "guarded-debug-1": (2, True)}


def run_statistics_fault_matrix(driver: Path, test: str, begin: str, end: str,
                                report_path: Path, reader: Path, *, release: bool = False,
                                selected: str | None = None, retained: Path | None = None) -> int:
    """Build or physically replay the selected regular-page fault controls."""
    harness.require_native_x86_64()
    root = retained if retained is not None else report_path.with_suffix("") / "matrix"
    root.mkdir(parents=True, exist_ok=True)
    profiles = {selected: PROFILES[selected]} if selected else {
        key: value for key, value in PROFILES.items() if key != "guarded-debug-1"}
    if release and selected == "guarded-debug-1":
        raise harness.HarnessError("guarded-debug-1 selects the regular-page extension controls")
    image = os.environ.get("CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID", "")
    if not image.startswith("sha256:") or len(image) != 71:
        raise harness.HarnessError("regular-page fault evidence requires the immutable execution image")
    pin = harness.load_pin()
    results = {}
    with harness.temporary_directory("crabc-statistics-page-fault-matrix-") as name:
        source = harness.safe_extract(harness.fetch_archive(pin, True), Path(name) / "source", pin["archive_root"]) if retained is None else None
        for profile, (level, debug) in profiles.items():
            guarded = profile == "guarded-debug-1"
            profile_root = root / profile
            profile_root.mkdir(exist_ok=True)
            if retained is None:
                compiled_input = profile_root / "compiled-input.c"
                shutil.copy2(driver, compiled_input)
                retained_archive = profile_root / "upstream.tar.gz"
                shutil.copy2(harness.fetch_archive(pin, True), retained_archive)
                features = []
                if guarded:
                    features.append("mi-guarded")
                if debug:
                    features.append("mi-debug-1")
                elif level:
                    features.append(f"mi-stat-{level}")
                build = harness.command_record([
                    harness.require_tool("cargo"), "test", "--locked", "--offline", "--target", TARGET,
                    "-p", "crabc-mimalloc", "--no-default-features",
                    *(["--features", ",".join(features)] if features else []),
                    "--lib", "--no-run", "--message-format=json", "--target-dir", str(m7.ARTIFACTS / "statistics-page-extension-fault/matrix" / profile / "cargo-target"),
                ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=m7.EVIDENCE_TIMEOUT_SECONDS)
                harness.write_json(profile_root / "rust-build.json", build)
                harness.require_success(build, f"{profile} page-fault test build")
                artifacts = []
                for line in build["stdout"].splitlines():
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if item.get("reason") == "compiler-artifact" and item.get("executable") and item.get("target", {}).get("name") == "crabc_mimalloc":
                        artifacts.append(Path(item["executable"]))
                if len(artifacts) != 1:
                    raise harness.HarnessError(f"{profile} did not produce one native allocator test binary")
                rust_binary = profile_root / "page-fault-rust"
                shutil.copy2(artifacts[0], rust_binary)
                unit_program = {"build": build, "build_command": build["command"],
                                "cargo_target": str(m7.ARTIFACTS / "statistics-page-extension-fault/matrix" / profile / "cargo-target"),
                                "artifact": harness.artifact_record(artifacts[0])}
                receipts.authenticate_unit_program(unit_program, features=[
                    *(["mi-guarded"] if guarded else []),
                    *(["mi-debug-1"] if debug else []),
                    *(["mi-stat-1"] if level else []),
                    *(["mi-stat-2"] if level == 2 else []),
                ])
                rust_execution_binary = artifacts[0]
            for control in ("fault", "success"):
                case = profile_root / control
                case.mkdir(exist_ok=True)
                path = case / "report.json"
                faulted = control == "fault"
                if retained is None:
                    flags = [f"-DMI_STAT={level}" if flag == "-DMI_STAT=0" else
                             "-DMI_GUARDED=1" if guarded and flag == "-DMI_GUARDED=0" else
                             "-DMI_DEBUG=1" if debug and flag == "-DMI_DEBUG=0" else flag
                             for flag in harness.CONFIGURATION_PROFILES["release"]
                             if not (debug and flag == "-DNDEBUG")]
                    c_binary = case / "page-fault-c"
                    c_build = harness.command_record([
                        harness.require_tool("musl-gcc"), "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
                        *flags, "-DCRABC_STATISTICS_MATRIX=1", f"-DCRABC_STAT_LEVEL={level}", f"-DCRABC_FAULTED={int(faulted)}",
                        "-Dmunmap=crabc_fault_munmap" if release else "-Dmprotect=crabc_fault_mprotect",
                        "-I", str(source / "include"), str(compiled_input), str(source / "src/static.c"), "-pthread", "-o", str(c_binary),
                    ], cwd=source)
                    report = {"status": "failed", "profile": profile, "level": level, "debug": debug,
                              "faulted": faulted, "c_build": c_build, "rust_build": build,
                              "provenance": {"pin": pin, "image": image, "git": m7.engine.git_provenance(),
                                             "source_seal": m7.integrated.source_seal(),
                                             "files": {key: m7.engine.file_record(value) for key, value in (
                                                 ("c_driver", driver), ("rust_page", harness.ROOT / "crabc-mimalloc/src/page.rs"),
                                                 ("reader", reader), ("shared_producer", Path(__file__)))}}}
                    harness.write_json(path, report)
                    harness.require_success(c_build, f"{profile}/{control} source page-fault build")
                    report["products"] = {"c": m7.engine.file_record(c_binary), "rust": m7.engine.file_record(rust_binary)}
                    report["physical_inputs"] = {"unit_program": unit_program,
                                                  "fixture": harness.artifact_record(compiled_input),
                                                  "archive": harness.artifact_record(retained_archive)}
                else:
                    report = json.loads(path.read_text())
                    if (report.get("status") != "passed" or report.get("profile") != profile
                            or report.get("level") != level or report.get("debug") != debug or report.get("faulted") != faulted
                            or report["provenance"].get("image") != image or not report["provenance"]["git"]["clean"]
                            or m7.integrated.source_seal_unmet(report["provenance"]["source_seal"])):
                        raise harness.HarnessError(f"retained {profile}/{control} has different source or mode")
                    for key, current in (("c_driver", driver), ("rust_page", harness.ROOT / "crabc-mimalloc/src/page.rs"),
                                         ("reader", reader), ("shared_producer", Path(__file__))):
                        if m7.engine.file_record(current)["sha256"] != report["provenance"]["files"][key]["sha256"]:
                            raise harness.HarnessError(f"retained {profile}/{control} changed {key}")
                    c_binary = case / Path(report["products"]["c"]["path"]).name
                    rust_binary = profile_root / Path(report["products"]["rust"]["path"]).name
                    for side, binary in (("c", c_binary), ("rust", rust_binary)):
                        actual = m7.engine.file_record(binary)
                        if any(actual[key] != report["products"][side][key] for key in ("sha256", "bytes")):
                            raise harness.HarnessError(f"retained {profile}/{control} changed {side} product")
                    if "physical_inputs" in report:
                        receipts.authenticate_artifacts(report["physical_inputs"], harness.ROOT)
                        unit_program = report["physical_inputs"]["unit_program"]
                        receipts.authenticate_unit_program(unit_program, features=[
                            *(["mi-guarded"] if guarded else []),
                            *(["mi-debug-1"] if debug else []),
                            *(["mi-stat-1"] if level else []),
                            *(["mi-stat-2"] if level == 2 else []),
                        ])
                        rust_binary = harness.ROOT / unit_program["artifact"]["path"]
                    elif guarded:
                        raise harness.HarnessError("guarded extension lacks original compiler product authority")
                    rust_execution_binary = rust_binary
                executions = {
                    "c": harness.command_record([str(c_binary.resolve())], cwd=case, env={}, timeout_seconds=60),
                    "rust": harness.command_record([str(rust_execution_binary.resolve()), test, "--exact", "--nocapture", "--test-threads=1"],
                                                   cwd=case, env={"CRABC_MI_STATISTICS_MATRIX": "1", "CRABC_MI_STATISTICS_FAULT_CONTROL": control},
                                                   timeout_seconds=m7.EVIDENCE_TIMEOUT_SECONDS),
                }
                if retained is None:
                    report["executions"] = executions
                    harness.write_json(path, report)
                traces = {}
                for side, execution in executions.items():
                    harness.require_success(execution, f"{profile}/{control} {side} page-fault execution")
                    traces[side] = m7.parse_options_trace(execution["stdout"], side, begin, end)
                if retained is None:
                    report.update(c_trace=traces["c"], rust_trace=traces["rust"])
                    harness.write_json(path, report)
                for side, trace in traces.items():
                    if any(trace.get(key) != value for key, value in (
                        ("profile.level", str(level)), ("profile.debug", str(int(debug))), ("profile.faulted", str(int(faulted))))):
                        raise harness.HarnessError(f"{side} {profile}/{control} lost its source statistics mode")
                    stages = ("allocated", "freed", "failed_release") if release else ("filled", "failed_allocation", "retry", "freed")
                    for stage in stages:
                        failures = int(faulted) if stage == "failed_release" or (not release and stage != "filled") else 0
                        if trace.get(f"{stage}.failures") != str(failures) or trace.get(f"{stage}.warnings") != str(failures):
                            raise harness.HarnessError(f"{side} {profile}/{control} did not reach the selected kernel fault")
                        if level == 0 and trace.get(f"{stage}.normal") != "0,0,0":
                            raise harness.HarnessError(f"{side} enabled disabled normal statistics")
                        if not release and level < 2 and trace.get(f"{stage}.requested") != "0,0,0":
                            raise harness.HarnessError(f"{side} enabled level-two requested statistics")
                    if not release:
                        if guarded and (trace.get("profile.guarded") != "1"
                                        or trace.get("profile.guarded_sample_rate") != "0"):
                            raise harness.HarnessError(f"{side} lost its actual guarded debug regular-page mode")
                        if any(trace.get(f"{stage}.client_bytes") != "1" for stage in ("failed_allocation", "retry")):
                            raise harness.HarnessError(f"{side} lost live regular client contents")
                        if faulted and trace.get("failed_allocation.original_prefix") != "1":
                            raise harness.HarnessError(f"{side} changed the exhausted prefix after refused commit")
                        if (int(trace.get("geometry.initial_capacity", "0")) <= 0
                                or trace.get("failed_allocation.nonnull") != "1" or trace.get("retry.nonnull") != "1"
                                or trace.get("failed_allocation.same_page") != str(int(not faulted)) or trace.get("retry.same_page") != "1"):
                            raise harness.HarnessError(f"{side} lost the filled-page fallback/retry boundary")
                        filled_extensions = int(trace.get("geometry.filled_extensions", "0"))
                        if (filled_extensions < 1 or trace.get("geometry.free_empty") != "1"
                                or trace.get("geometry.used") != trace.get("geometry.filled_capacity")
                                or int(trace.get("geometry.filled_capacity", "0")) < int(trace["geometry.initial_capacity"])):
                            raise harness.HarnessError(f"{side} did not exhaust the actual source page capacity")
                        extensions = (filled_extensions, filled_extensions + 2, filled_extensions + 3, filled_extensions + 3) if faulted else (filled_extensions, filled_extensions + 1, filled_extensions + 1, filled_extensions + 1)
                        if any(trace.get(f"{stage}.pages_extended") != str(value if level else 0)
                               for stage, value in zip(stages, extensions)):
                            raise harness.HarnessError(f"{side} charged the wrong extension attempts")
                if release:
                    from x86_64_m7_statistics_regular_page_release_fault import comparable_trace
                    compared = {side: comparable_trace(trace, level=level, debug=debug, faulted=faulted) for side, trace in traces.items()}
                else:
                    compared = traces
                    if level == 2 and not debug and faulted:
                        metadata = {"profile.debug", "profile.faulted", "profile.guarded", "profile.guarded_sample_rate",
                                    "failed_allocation.original_prefix", "failed_allocation.client_bytes", "retry.client_bytes"} | {key for key in trace if key.startswith("geometry.")}
                        for side, trace in traces.items():
                            m7.require_statistics_page_extend({key: value for key, value in trace.items() if key not in metadata}, side, faulted=True)
                mismatch = {key: {side: compared[side].get(key) for side in compared} for key in set(compared["c"]) | set(compared["rust"])
                            if compared["c"].get(key) != compared["rust"].get(key)}
                if retained is None:
                    report.update(compared_trace=compared, mismatch=mismatch, compared_key_count=len(compared["c"]),
                                  status="failed" if mismatch else "passed")
                    harness.write_json(path, report)
                else:
                    if any((compared[side] != report["compared_trace"][side] if release
                            else traces[side] != report[f"{side}_trace"]) for side in traces):
                        raise harness.HarnessError(f"retained {profile}/{control} changed compared observable statistics")
                if retained is not None:
                    physical_report = dict(report)
                    physical_report.update(executions=executions, c_trace=traces["c"], rust_trace=traces["rust"],
                                           compared_trace=compared, mismatch=mismatch,
                                           status="failed" if mismatch else "passed")
                    harness.write_json(case / "physical-replay.json", physical_report)
                if mismatch:
                    raise harness.HarnessError(f"{profile}/{control} source page-fault statistics differ: {mismatch}")
                results[f"{profile}/{control}"] = "passed"
                print(f"{profile}/{control}: passed {len(compared['c'])} exact fields", flush=True)
    if retained is None:
        harness.write_json(root / "report.json", {"status": "passed", "profiles": results,
                           "provenance": {"git": m7.engine.git_provenance(), "source_seal": m7.integrated.source_seal()}})
    else:
        summary = json.loads((root / "report.json").read_text())
        if summary.get("status") != "passed" or summary.get("profiles") != results:
            raise harness.HarnessError("retained page fault controls are incomplete")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--profile", choices=PROFILES)
    parser.add_argument("--read-matrix", type=Path)
    args = parser.parse_args()
    if args.matrix or args.read_matrix is not None:
        if args.matrix and args.read_matrix is not None:
            parser.error("physical replay cannot produce a matrix")
        return run_statistics_fault_matrix(DRIVER, TEST, BEGIN, END, REPORT, Path(__file__),
                                           selected=args.profile, retained=args.read_matrix)
    if args.profile is not None:
        parser.error("--profile requires --matrix or --read-matrix")
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, args.offline)
    with harness.temporary_directory("crabc-m7-statistics-page-extension-fault-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        flags = ["-DMI_STAT=2" if flag == "-DMI_STAT=0" else flag
                 for flag in harness.CONFIGURATION_PROFILES["release"]]
        c_binary = temporary / "page-extension-fault-c"
        c_build = harness.command_record([
            compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
            *flags, "-Dmprotect=crabc_fault_mprotect",
            "-I", str(source / "include"), str(DRIVER),
            str(source / "src/static.c"), "-pthread", "-o", str(c_binary),
        ], cwd=source)
        harness.require_success(c_build, "pinned page-extension fault C build")
        c_run = harness.command_record([str(c_binary)], cwd=temporary, env={}, timeout_seconds=60)
        harness.require_success(c_run, "pinned page-extension fault C execution")

        cargo = harness.require_tool("cargo")
        target_dir = temporary / "cargo-target"
        rust_run = harness.command_record([
            cargo, "test", "--locked", "--offline", "--target", TARGET,
            "-p", "crabc-mimalloc", "--no-default-features", "--features", "mi-stat-2",
            "--lib", TEST, "--target-dir", str(target_dir),
            "--", "--exact", "--nocapture", "--test-threads=1",
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=m7.EVIDENCE_TIMEOUT_SECONDS)
        harness.require_success(rust_run, "native page-extension fault test")

        traces = {
            "c": m7.parse_options_trace(str(c_run["stdout"]), "pinned page-extension fault", BEGIN, END),
            "rust": m7.parse_options_trace(str(rust_run["stdout"]), "native page-extension fault", BEGIN, END),
        }
        report = {
            "status": "failed", "c_trace": traces["c"], "rust_trace": traces["rust"],
            "c_build": c_build["command"], "c_run": c_run["command"],
            "rust_test": rust_run["command"],
            "fault_placement": "one failed write-enable after 128 live 64-byte blocks; later commits reach the kernel",
            "provenance": {
                "pin": {key: pin[key] for key in ("tag", "revision", "sha256")},
                "git": m7.engine.git_provenance(),
                "source_seal": m7.integrated.source_seal(),
                "files": {name: m7.engine.file_record(path) for name, path in (
                    ("c_driver", DRIVER), ("rust_page", harness.ROOT / "crabc-mimalloc/src/page.rs"),
                    ("reader", Path(__file__)),
                )},
            },
        }
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        harness.write_json(REPORT, report)
        for side in ("c", "rust"):
            m7.require_statistics_page_extend(traces[side], f"{side} page-extension fault", faulted=True)
        m7.compare_options_traces(traces["c"], traces["rust"])
        report["compared_key_count"] = len(traces["c"])
        report["status"] = "passed"
        harness.write_json(REPORT, report)
    print(f"Page-extension commit fault: passed ({report['compared_key_count']} exact keys)")
    print(REPORT)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
