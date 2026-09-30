#!/usr/bin/env python3
"""Compare public MI_STAT=2 accounting after one failed regular OS page release."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import run as harness
import x86_64_m7_gate as m7


DRIVER = harness.ALLOCATOR_ROOT / "x86_64_m7_statistics_regular_page_release_fault_driver.c"
TEST = "page::tests::failed_regular_page_release_preserves_source_statistics"
BEGIN = "CRABC_MI_M7_PAGE_FAILURE_STATS_TRACE_BEGIN"
END = "CRABC_MI_M7_PAGE_FAILURE_STATS_TRACE_END"
REPORT = m7.ARTIFACTS / "statistics-regular-page-release-fault.json"
TARGET = "x86_64-unknown-linux-musl"
VM_FIELDS = ("reserved", "committed")


def comparable_trace(raw: dict[str, str], *, level: int = 2, debug: bool = False, faulted: bool = True) -> dict[str, str]:
    """Compare VM transitions while retaining placement-sensitive raw images."""
    normal = (int(raw.get("geometry.block_size", "64")) - (8 if debug else 0)) if level else 0
    bin_index = 9 if debug else 8
    expected = {
        "profile.level": str(level),
        "profile.disallow_arena": "1",
        "allocated.pages": "1,0,1",
        "allocated.normal": f"{normal},0,{normal}",
        "allocated.page_bin": f"{bin_index}:1,1",
        "allocated.warnings": "0",
        "allocated.failures": "0",
        "freed.pages": "1,0,1",
        "freed.normal": f"{normal},0,0",
        "freed.page_bin": f"{bin_index}:1,1",
        "freed.warnings": "0",
        "freed.failures": "0",
        "failed_release.pages": "1,0,0",
        "failed_release.normal": f"{normal},0,0",
        "failed_release.page_bin": f"{bin_index}:1,0",
        "failed_release.warnings": str(int(faulted)),
        "failed_release.failures": str(int(faulted)),
    }
    for key, value in expected.items():
        if raw.get(key) != value:
            raise harness.HarnessError(
                f"regular-page release shape {key}: expected {value}, got {raw.get(key)}"
            )
    compared = {key: value for key, value in raw.items()
                if not any(key.endswith(f".{field}") for field in VM_FIELDS)}
    for field in VM_FIELDS:
        stages = {}
        for stage in ("allocated", "freed", "failed_release"):
            key = f"{stage}.{field}"
            try:
                values = tuple(int(value) for value in raw[key].split(","))
            except (KeyError, ValueError) as error:
                raise harness.HarnessError(f"invalid {key} VM count in release trace") from error
            if len(values) != 3:
                raise harness.HarnessError(f"invalid {key} VM count width in release trace")
            stages[stage] = values
        for later, earlier in (("freed", "allocated"), ("failed_release", "freed")):
            delta = tuple(left - right for left, right in zip(stages[later], stages[earlier]))
            if later == "failed_release" and delta[2] >= 0:
                raise harness.HarnessError(f"failed page release did not reduce {field} current")
            compared[f"{later}_minus_{earlier}.{field}"] = ",".join(str(value) for value in delta)
    if raw.get("failed_release.failures") != str(int(faulted)) or raw.get("failed_release.warnings") != str(int(faulted)):
        raise harness.HarnessError("the OS page release fault did not produce one failure and warning")
    if raw.get("failed_release.pages", "").split(",")[-1] != "0":
        raise harness.HarnessError("forced collection did not release the page count")
    return compared


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    from x86_64_m7_statistics_page_extension_fault import PROFILES, run_statistics_fault_matrix
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--profile", choices=PROFILES)
    parser.add_argument("--read-matrix", type=Path)
    args = parser.parse_args()
    if args.matrix or args.read_matrix is not None:
        if args.matrix and args.read_matrix is not None:
            parser.error("physical replay cannot produce a matrix")
        return run_statistics_fault_matrix(DRIVER, TEST, BEGIN, END, REPORT, Path(__file__),
                                           release=True, selected=args.profile, retained=args.read_matrix)
    if args.profile is not None:
        parser.error("--profile requires --matrix or --read-matrix")
    harness.require_native_x86_64()
    pin = harness.load_pin()
    archive = harness.fetch_archive(pin, args.offline)
    with harness.temporary_directory("crabc-m7-page-failure-stats-") as name:
        temporary = Path(name)
        source = harness.safe_extract(archive, temporary / "source", pin["archive_root"])
        flags = ["-DMI_STAT=2" if flag == "-DMI_STAT=0" else flag
                 for flag in harness.CONFIGURATION_PROFILES["release"]]
        c_binary = temporary / "page-failure-stats-c"
        c_build = harness.command_record([
            harness.require_tool("musl-gcc"), "-std=c11", "-ftls-model=initial-exec",
            "-DMI_LIBC_MUSL=1", *flags, "-Dmunmap=crabc_fault_munmap",
            "-I", str(source / "include"), str(DRIVER),
            str(source / "src/static.c"), "-pthread", "-o", str(c_binary),
        ], cwd=source)
        harness.require_success(c_build, "pinned regular-page-release fault C build")
        c_run = harness.command_record([str(c_binary)], cwd=temporary, env={}, timeout_seconds=60)
        harness.require_success(c_run, "pinned regular-page-release fault C execution")

        target_dir = temporary / "cargo-target"
        rust_run = harness.command_record([
            harness.require_tool("cargo"), "test", "--locked", "--offline", "--target", TARGET,
            "-p", "crabc-mimalloc", "--no-default-features", "--features", "mi-stat-2",
            "--lib", TEST, "--target-dir", str(target_dir),
            "--", "--exact", "--nocapture", "--test-threads=1",
        ], cwd=harness.ROOT, env=dict(os.environ), timeout_seconds=m7.EVIDENCE_TIMEOUT_SECONDS)
        report = {
            "status": "failed",
            "c_build": c_build, "c_run": c_run, "rust_test": rust_run,
            "fault_placement": "one failed munmap after allocation of an OS-backed regular page",
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
        harness.require_success(rust_run, "native regular-page-release fault test")
        traces = {
            "c": m7.parse_options_trace(str(c_run["stdout"]), "pinned regular-page-release fault", BEGIN, END),
            "rust": m7.parse_options_trace(str(rust_run["stdout"]), "native regular-page-release fault", BEGIN, END),
        }
        report.update(c_trace=traces["c"], rust_trace=traces["rust"])
        harness.write_json(REPORT, report)
        compared = {side: comparable_trace(trace) for side, trace in traces.items()}
        report["compared_trace"] = compared
        harness.write_json(REPORT, report)
        m7.compare_options_traces(compared["c"], compared["rust"])
        report["compared_key_count"] = len(compared["c"])
        report["status"] = "passed"
        harness.write_json(REPORT, report)
    print(f"Regular-page-release failure statistics: passed ({report['compared_key_count']} exact keys)")
    print(REPORT)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
