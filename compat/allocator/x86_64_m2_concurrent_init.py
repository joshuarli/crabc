#!/usr/bin/env python3
"""Compare process-body and loader-tail callback races with pinned C."""

from __future__ import annotations

import argparse
import importlib.util
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "compat/allocator/x86_64_m2_concurrent_init.c"
REPORT = ROOT / "compat/reports/allocator/x86_64/concurrent-process-init.json"
SCHEMA = ROOT / "compat/allocator/x86_64-init-recursion-evidence-v3.5.0.json"
RUST_TEST = "process_init::tests::emit_m2_concurrent_process_init_callback_c_rust_trace"
TAIL_RUST_TEST = "process_init::tests::emit_m2_loader_tail_once_release_c_rust_trace"
TAIL_FIELDS = (
    "ready_before_tail_output",
    "recursive_init_complete",
    "contender_completes_during_tail",
    "default_owner_preserved",
    "counters_preserved",
    "tail_claim_not_repeated",
)
FIELDS = (
    "initialized_at_callback",
    "reentry_preserves_owner",
    "contender_waits",
    "ready_owner_stable",
    "contender_observed_ready",
    "contender_no_tld",
    "counters_preserved",
    "owner_identity_preserved",
)

spec = importlib.util.spec_from_file_location("crabc_allocator_runner", ROOT / "compat/allocator/run.py")
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


def parse_trace(output: str, language: str, *, tail: bool = False) -> dict[str, int]:
    marker = "LOADER_TAIL" if tail else "CONCURRENT_INIT"
    prefix = "loader_tail" if tail else "concurrent_init"
    expected = TAIL_FIELDS if tail else FIELDS
    begin = f"CRABC_MI_{marker}_{language}_TRACE_BEGIN"
    end = f"CRABC_MI_{marker}_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise ValueError(f"{language} concurrent-init trace has no single marked record")
    body = output.split(begin, 1)[1].split(end, 1)[0]
    fields: dict[str, int] = {}
    for line in body.splitlines():
        match = re.fullmatch(rf"trace\.{prefix}\.([a-z_]+)=([01])", line.strip())
        if match is None:
            if line.strip():
                raise ValueError(f"{language} concurrent-init trace contains an invalid field")
            continue
        if match[1] in fields:
            raise ValueError(f"{language} concurrent-init trace repeats {match[1]}")
        fields[match[1]] = int(match[2])
    if set(fields) != set(expected):
        raise ValueError(f"{language} concurrent-init trace field set changed")
    return fields


def compare(c_record: dict[str, int], rust_record: dict[str, int]) -> None:
    if c_record != rust_record:
        raise ValueError("pinned C and Rust concurrent process-init observations differ")
    if any(value != 1 for value in c_record.values()):
        raise ValueError("concurrent process-init ownership invariant failed")


def execute(command: list[str], *, cwd: Path, timeout: int = 180) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=timeout,
                            env=os.environ.copy(), check=False)
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n"
                           f"{result.stdout}\n{result.stderr}")
    return result.stdout + "\n" + result.stderr


def collect() -> dict[str, object]:
    native = run.require_native_x86_64()
    source_inputs = (FIXTURE, Path(__file__).resolve(), ROOT / "crabc-mimalloc/src/process_init.rs")
    before = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_inputs}
    pin = run.load_pin()
    archive = run.fetch_archive(pin, True)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    scratch = ROOT / ".work/allocator-x86_64/tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="concurrent-init-", dir=scratch) as directory:
        work = Path(directory)
        source = run.safe_extract(archive, work / "source", pin["archive_root"])
        c_binary = work / "concurrent-init-c"
        c_command = [
            run.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
            *schema["compile_definitions"], "-I", str(source / "include"),
            "-I", str(source / "src"), *schema["release_flags"], str(FIXTURE),
            *(str(source / member) for member in schema["release_source_set"]),
            "-pthread", "-Wl,--wrap=fputs", "-o", str(c_binary),
        ]
        execute(c_command, cwd=source)
        c_output = execute([str(c_binary)], cwd=source, timeout=30)
        c_record = parse_trace(c_output, "C")
        rust_command = [
            run.require_tool("cargo"), "test", "--locked", "--target", "x86_64-unknown-linux-musl",
            "--target-dir", str(ROOT / ".work/allocator-x86_64/target"), "-p", "crabc-mimalloc", "--lib",
            "--no-default-features", RUST_TEST, "--", "--exact", "--nocapture", "--test-threads=1",
        ]
        rust_output = execute(rust_command, cwd=ROOT, timeout=600)
        if run.parse_rust_test_count(rust_output) != 1:
            raise ValueError("the Rust concurrent-init observer did not pass exactly once")
        rust_record = parse_trace(rust_output, "RUST")
        compare(c_record, rust_record)
        tail_c_output = execute([str(c_binary), "loader-tail"], cwd=source, timeout=30)
        tail_c_record = parse_trace(tail_c_output, "C", tail=True)
        tail_rust_command = [TAIL_RUST_TEST if item == RUST_TEST else item for item in rust_command]
        tail_rust_output = execute(tail_rust_command, cwd=ROOT, timeout=600)
        if run.parse_rust_test_count(tail_rust_output) != 1:
            raise ValueError("the Rust loader-tail observer did not pass exactly once")
        tail_rust_record = parse_trace(tail_rust_output, "RUST", tail=True)
        compare(tail_c_record, tail_rust_record)
        raw_directory = REPORT.parent / "concurrent-process-init"
        raw_directory.mkdir(parents=True, exist_ok=True)
        raw = {}
        for name, output in (
            ("process-body-c", c_output), ("process-body-rust", rust_output),
            ("loader-tail-c", tail_c_output), ("loader-tail-rust", tail_rust_output),
        ):
            path = raw_directory / f"{name}.log"
            path.write_text(output, encoding="utf-8")
            raw[name] = {"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        after = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_inputs}
        if before != after:
            raise ValueError("concurrent initialization source changed during collection")
        provenance = {
            "source_inputs": after,
            "native": native,
            "fixture_sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
            "rust_source_sha256": hashlib.sha256((ROOT / "crabc-mimalloc/src/process_init.rs").read_bytes()).hexdigest(),
            "c_elf_sha256": hashlib.sha256(c_binary.read_bytes()).hexdigest(),
            "compile_command": c_command,
            "rust_commands": [rust_command, tail_rust_command],
        }
    return {
        "scope": "source process-body reservation failure callback and subsequent loader-tail delayed stderr flush; opposite once-lock boundaries",
        "raw": raw,
        "provenance": provenance,
        "loader_tail": {"c": tail_c_record, "rust": tail_rust_record, "comparison": "matched"},
        "upstream_version": pin["version"],
        "upstream_revision": pin["revision"],
        "c": c_record,
        "rust": rust_record,
        "comparison": "matched",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", required=True)
    args = parser.parse_args()
    del args
    report = collect()
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"concurrent process initialization: {report['comparison']} ({len(FIELDS) + len(TAIL_FIELDS)} fields)")
    print(REPORT.relative_to(ROOT))


if __name__ == "__main__":
    main()
