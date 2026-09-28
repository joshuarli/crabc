#!/usr/bin/env python3
"""Link one medium-page trace against the source-built C and Rust engine objects."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from compat.allocator import perf_engine_x86_64 as engine


ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "compat/allocator/medium_queue_head_trace.c"
BLOCK_COUNT = 16
ALLOC = re.compile(r"alloc (fresh|repeat) ([0-9]+) usable=([0-9]+) align=([0-9]+)")
DRAIN = re.compile(r"drain (fresh|repeat) count=16")
REPLACE = re.compile(r"replace (fresh|repeat) reused=([01]) usable=([0-9]+) align=([0-9]+)")
SPILL = re.compile(r"spill (fresh|repeat) usable=([0-9]+) align=([0-9]+)")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_trace(raw: str) -> list[tuple[str, str, int, int, int]]:
    events: list[tuple[str, str, int, int, int]] = []
    for line in raw.splitlines():
        if match := ALLOC.fullmatch(line):
            phase, index, usable, alignment = match.groups()
            events.append(("alloc", phase, int(index), int(usable), int(alignment)))
        elif match := REPLACE.fullmatch(line):
            phase, reused, usable, alignment = match.groups()
            events.append(("replace", phase, int(reused), int(usable), int(alignment)))
        elif match := SPILL.fullmatch(line):
            phase, usable, alignment = match.groups()
            events.append(("spill", phase, BLOCK_COUNT, int(usable), int(alignment)))
        elif match := DRAIN.fullmatch(line):
            events.append(("drain", match.group(1), BLOCK_COUNT, 0, 0))
        else:
            raise ValueError(f"unexpected medium trace line: {line!r}")
    expected = []
    for phase in ("fresh", "repeat"):
        expected.extend(("alloc", phase, index, None, 0) for index in range(BLOCK_COUNT))
        expected.append(("replace", phase, 1, None, 0))
        expected.append(("spill", phase, BLOCK_COUNT, None, 0))
        expected.append(("drain", phase, BLOCK_COUNT, 0, 0))
    if len(events) != len(expected):
        raise ValueError("medium trace lacks a fresh or repeated allocation/drain event")
    for actual, shape in zip(events, expected):
        if actual[:3] != shape[:3] or actual[4] != shape[4]:
            raise ValueError(f"medium trace order or alignment differs: {actual!r}")
        if actual[0] in ("alloc", "replace", "spill") and actual[3] < 32768:
            raise ValueError(f"medium trace usable size is too small: {actual!r}")
    return events


def command(arguments: list[str], *, cwd: Path) -> dict[str, object]:
    completed = subprocess.run(arguments, cwd=cwd, text=True, capture_output=True, check=False)
    record = {"argv": arguments, "status": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}
    if completed.returncode != 0:
        raise RuntimeError(f"command failed: {record}")
    return record


def run(codegen_report: Path, output: Path) -> dict[str, object]:
    source = json.loads(codegen_report.read_text(encoding="utf-8"))
    recorded_git = source["provenance"]["git"]
    current_git = engine.git_provenance()
    diagnostic_paths = {
        "?? compat/allocator/medium_queue_head_trace.c",
        "?? compat/allocator/medium_queue_head_trace.py",
        "?? compat/allocator/tests/test_medium_queue_head_trace.py",
    }
    if recorded_git["head"] != current_git["head"] or (
        set(recorded_git["dirty_paths"]) - diagnostic_paths
        != set(current_git["dirty_paths"]) - diagnostic_paths
    ):
        raise ValueError("codegen products do not match the current allocator source")
    artifacts = codegen_report.with_suffix(".artifacts")
    manifest = engine.load_manifest()
    compiler = engine.shared.require_tool("musl-gcc")
    output.mkdir(parents=True, exist_ok=False)
    driver = output / "medium-queue-head.o"
    flags = manifest["shared_build"]["fixture_flags"]
    build = [command([compiler, *flags, "-I", str(ROOT / "compat/allocator"), "-c", str(DRIVER), "-o", str(driver)], cwd=ROOT)]
    c_objects = [
        artifacts / ("mimalloc-" + item.replace("/", "-").removesuffix(".c") + ".o")
        for item in engine.shared.ORACLE_SOURCES
    ]
    links = {
        "pinned_c": [artifacts / "engine-c-backend.o", *c_objects],
        "rust_engine": [artifacts / "libcrabc_allocator_engine_rust_backend.a"],
    }
    traces = {}
    for lane, objects in links.items():
        binary = output / lane
        build.append(command([compiler, *manifest["shared_build"]["link_flags"], str(driver), *(str(item) for item in objects), "-o", str(binary)], cwd=ROOT))
        execution = command([str(binary)], cwd=ROOT)
        events = read_trace(str(execution["stdout"]))
        traces[lane] = {"product_sha256": digest(binary), "stdout": execution["stdout"], "events": events}
    if traces["pinned_c"]["events"] != traces["rust_engine"]["events"]:
        raise ValueError("pinned C and Rust medium traces differ")
    report = {
        "source_codegen_report": {"path": str(codegen_report), "sha256": digest(codegen_report)},
        "source_git": source["provenance"]["git"],
        "driver_sha256": digest(DRIVER),
        "build": build,
        "traces": traces,
        "status": "matched",
    }
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codegen-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    result = run(arguments.codegen_report.resolve(), arguments.output.resolve())
    print(arguments.output / "report.json", result["status"])
