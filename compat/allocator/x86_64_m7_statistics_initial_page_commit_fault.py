#!/usr/bin/env python3
"""Compare statistics after a failed initial regular-page commit and recovery."""

from __future__ import annotations

import argparse
import os
import json
import shutil
import sys
from pathlib import Path

import run as harness
import x86_64_m7_gate as m7
import x86_64_foundation_gate_receipts as receipts


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_initial_page_commit_fault_driver.c"
TEST = "page::tests::failed_initial_regular_page_commit_recovers_source_statistics"
BEGIN = "CRABC_MI_M7_INITIAL_PAGE_COMMIT_FAULT_TRACE_BEGIN"
END = "CRABC_MI_M7_INITIAL_PAGE_COMMIT_FAULT_TRACE_END"
REPORT = m7.ARTIFACTS / "statistics-initial-page-commit-fault.json"
PROFILES = {"guarded-stat-0": (0, False), "guarded-stat-1": (1, False),
            "guarded-stat-2": (2, False), "guarded-debug-1": (2, True)}


def require_commit_failure_shape(trace: dict[str, str], side: str, *,
                                 profile: str | None = None, faulted: bool = True) -> None:
    if profile is not None:
        level, debug = PROFILES[profile]
        expected = {"profile.level": str(level), "profile.debug": str(int(debug)),
                    "profile.guarded": "1", "profile.faulted": str(int(faulted)),
                    "profile.sample_rate": "0", "profile.theap_sample_rate": "0",
                    "profile.on_demand": "1", "profile.eager_arena": "0", "profile.show_errors": "1",
                    "fault.nonnull": "1", "fault.commit_size": "114688", "recovery.nonnull": "1",
                    "recovery.client_bytes": "1", "recovery.clients_distinct": "1",
                    "recovery.clients_owned": "1"}
        for stage in ("fault", "recovery", "freed"):
            expected[stage + ".failures"] = str(int(faulted))
            expected[stage + ".warnings"] = str(int(faulted))
            if level == 0:
                expected[stage + ".normal"] = "0,0,0"
            if level < 2:
                expected[stage + ".requested"] = "0,0,0"
        for key, value in expected.items():
            if trace.get(key) != value:
                raise harness.HarnessError(f"{side} {profile} initial-page commit shape {key}: expected {value}, got {trace.get(key)}")
        return
    expected = {
        "profile.level": "2",
        "profile.on_demand": "1",
        "profile.eager_arena": "0",
        "profile.show_errors": "1",
        "before.pages": "0,0,0",
        "before.page_committed": "0,0,0",
        "before.commit_calls": "0",
        "fault.nonnull": "1",
        "fault.commit_size": "114688",
        "fault.pages": "1,1,1",
        "fault.page_committed": "114688,114688,114688",
        "fault.bin": "51:1,1,1",
        "fault.page_bin": "51:1,1",
        "fault.commit_calls": "2",
        "fault.warnings": "1",
        "fault.failures": "1",
        "recovery.nonnull": "1",
        "recovery.pages": "1,1,1",
        "recovery.page_committed": "229376,229376,229376",
        "recovery.bin": "51:2,2,2",
        "recovery.page_bin": "51:1,1",
        "recovery.commit_calls": "3",
        "recovery.warnings": "1",
        "recovery.failures": "1",
        "freed.pages": "1,1,1",
        "freed.normal": "229376,229312,0",
        "freed.bin": "51:2,2,0",
        "freed.page_bin": "51:1,1",
        "freed.commit_calls": "3",
        "freed.warnings": "1",
        "freed.failures": "1",
    }
    for key, value in expected.items():
        if trace.get(key) != value:
            raise harness.HarnessError(
                f"{side} initial-page commit shape {key}: expected {value}, got {trace.get(key)}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--profile", choices=PROFILES)
    args = parser.parse_args()
    level, debug = PROFILES[args.profile] if args.profile else (2, False)
    execution_before = harness.require_native_x86_64(require_image_identity=True)
    source_before = m7.integrated.source_seal()
    git_before = m7.engine.git_provenance()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, args.offline)
    artifacts = REPORT.with_suffix("")
    if args.profile:
        artifacts = artifacts / "matrix" / args.profile
    artifacts.mkdir(parents=True, exist_ok=True)
    compiled_input = artifacts / "compiled-input.c"
    shutil.copy2(DRIVER, compiled_input)
    retained_archive = artifacts / "upstream.tar.gz"
    shutil.copy2(archive, retained_archive)
    with harness.temporary_directory("crabc-m7-statistics-initial-page-commit-fault-") as name:
        temporary = Path(name)
        source = harness.safe_extract(retained_archive, artifacts / "source", pin["archive_root"])
        compiler = harness.require_tool("musl-gcc")
        flags = [f"-DMI_STAT={level}" if flag == "-DMI_STAT=0" else
                 "-DMI_DEBUG=1" if debug and flag == "-DMI_DEBUG=0" else
                 "-DMI_GUARDED=1" if args.profile and flag == "-DMI_GUARDED=0" else flag
                 for flag in harness.CONFIGURATION_PROFILES["release"]
                 if not (debug and flag == "-DNDEBUG")]
        if args.profile:
            flags.append("-DCRABC_STATISTICS_MATRIX=1")
        c_binary = artifacts / "oracle"
        c_build = harness.command_record([
            compiler, "-std=c11", "-ftls-model=initial-exec", "-DMI_LIBC_MUSL=1",
            *flags, "-Dmprotect=crabc_fault_mprotect",
            "-I", str(source / "include"), str(compiled_input),
            str(source / "src/static.c"), "-pthread", "-o", str(c_binary),
        ], cwd=source)
        harness.write_json(artifacts / "c-build.json", c_build)
        harness.require_success(c_build, "pinned initial-page commit fault C build")
        first_case = artifacts / "fault" if args.profile else artifacts
        first_case.mkdir(exist_ok=True)
        first_environment = {"CRABC_MI_STATISTICS_MATRIX": "1",
                             "CRABC_MI_STATISTICS_FAULT_CONTROL": "fault"} if args.profile else {}
        first_c_run = harness.command_record([str(c_binary)], cwd=temporary, env=first_environment, timeout_seconds=60)
        harness.write_json(first_case / "c-execute.json", first_c_run)
        harness.require_success(first_c_run, "pinned initial-page commit fault C execution")
        features = (["mi-debug-1"] if debug else [f"mi-stat-{level}"] if level else [])
        if args.profile:
            features.append("mi-guarded")
        expected_features = (["mi-debug-1", "mi-stat-1", "mi-stat-2"] if debug else
                             ["mi-stat-1", "mi-stat-2"] if level == 2 else
                             ["mi-stat-1"] if level == 1 else [])
        if args.profile:
            expected_features = sorted([*expected_features, "mi-guarded"])
        manifest = harness.ROOT / "crabc-mimalloc/Cargo.toml"
        command = [harness.require_tool("cargo"), "test", "--manifest-path", str(manifest),
                   "--locked", "--offline", "--target", "x86_64-unknown-linux-musl",
                   "--lib", "--no-default-features"]
        if features:
            command.extend(("--features", ",".join(features)))
        command.extend(("--no-run", "--message-format=json"))
        build = harness.command_record(command, cwd=harness.ROOT, timeout_seconds=3600)
        harness.write_json(artifacts / "rust-build.json", build)
        harness.require_success(build, "initial-page commit test product build")
        candidates = []
        for line in str(build["stdout"]).splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (isinstance(event, dict) and event.get("reason") == "compiler-artifact"
                    and event.get("manifest_path") == str(manifest)
                    and event.get("target", {}).get("name") == "crabc_mimalloc"
                    and event.get("target", {}).get("src_path") == str(manifest.parent / "src/lib.rs")
                    and event.get("target", {}).get("kind") == ["lib"]
                    and event.get("profile", {}).get("test") is True
                    and event.get("features") == expected_features
                    and isinstance(event.get("executable"), str)):
                candidates.append(event)
        if len(candidates) != 1:
            raise harness.HarnessError("initial-page commit compiler executable authority differs")
        selected = candidates[0]
        harness.write_json(artifacts / "compiler-artifact.json", selected)
        program = {"path": Path(selected["executable"]),
                   "execution": {"test_threads": 1, "timeout_seconds": 180}}
        unit_program = {"build": build, "build_command": build["command"],
                        "cargo_target": str(harness.WORK_ROOT / "target"),
                        "execution": program["execution"],
                        "artifact": harness.artifact_record(program["path"])}
        receipts.authenticate_unit_program(unit_program, features=expected_features)
        controls = ("fault", "success") if args.profile else ("fault",)
        for control in controls:
            case = artifacts / control if args.profile else artifacts
            case.mkdir(exist_ok=True)
            report_path = case / "report.json" if args.profile else REPORT
            environment = {"CRABC_MI_STATISTICS_MATRIX": "1",
                           "CRABC_MI_STATISTICS_FAULT_CONTROL": control} if args.profile else {}
            c_run = first_c_run if control == "fault" else harness.command_record([str(c_binary)], cwd=temporary, env=environment, timeout_seconds=60)
            harness.write_json(case / "c-execute.json", c_run)
            harness.require_success(c_run, "pinned initial-page commit fault C execution")
            rust_run = harness.command_record(harness._x86_64_program_check_command(
                program, TEST, nocapture=True, gate_name="initial-page commit fault"),
                cwd=harness.ROOT, env={**os.environ, **environment}, timeout_seconds=m7.EVIDENCE_TIMEOUT_SECONDS)
            harness.write_json(case / "rust-execute.json", rust_run)
            report = {
                "status": "failed", "c_build": c_build, "c_run": c_run,
                "rust_test": rust_run,
                "fault_placement": "one failed initial page write-enable after arena warmup; subsequent page commits reach the kernel",
                "physical_inputs": {
                    "unit_program": unit_program,
                    "c_program": harness.artifact_record(c_binary),
                    "fixture": harness.artifact_record(compiled_input),
                    "archive": harness.artifact_record(retained_archive),
                    "oracle_source": harness.source_file_records(source, sorted(
                        path.relative_to(source).as_posix()
                        for parent in (source / "include", source / "src")
                        for path in parent.rglob("*") if path.is_file())),
                },
                "native_execution_provenance": harness.native_execution_attestation(
                    execution_before, harness.require_native_x86_64(require_image_identity=True)),
                "provenance": {
                    "pin": {key: pin[key] for key in ("tag", "revision", "sha256")},
                    "git": git_before,
                    "source_seal": source_before,
                    "files": {name: m7.engine.file_record(path) for name, path in (
                        ("c_driver", DRIVER), ("rust_page", harness.ROOT / "crabc-mimalloc/src/page.rs"),
                        ("reader", Path(__file__)),
                    )},
                },
            }
            if args.profile:
                report.update(profile=args.profile, level=level, debug=debug, faulted=control == "fault")
            harness.write_json(report_path, report)
            if m7.integrated.source_seal() != source_before or m7.engine.git_provenance() != git_before:
                raise harness.HarnessError("initial-page commit source changed during collection")
            harness.require_success(rust_run, "native initial-page commit fault test")
            if harness.parse_rust_test_count(str(rust_run["stdout"]) + str(rust_run["stderr"])) != 1:
                raise harness.HarnessError("initial-page commit selection did not execute one passing test")
            traces = {
                "c": m7.parse_options_trace(str(c_run["stdout"]), "pinned initial-page commit fault", BEGIN, END),
                "rust": m7.parse_options_trace(str(rust_run["stdout"]), "native initial-page commit fault", BEGIN, END),
            }
            report.update(c_trace=traces["c"], rust_trace=traces["rust"])
            harness.write_json(report_path, report)
            for side in ("c", "rust"):
                require_commit_failure_shape(traces[side], side, profile=args.profile, faulted=control == "fault")
            m7.compare_options_traces(traces["c"], traces["rust"])
            report["compared_key_count"] = len(traces["c"])
            report["status"] = "passed"
            harness.write_json(report_path, report)
            print(f"Initial-page commit {args.profile or 'stat-2'}/{control}: passed ({report['compared_key_count']} exact keys)")
            print(report_path)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
