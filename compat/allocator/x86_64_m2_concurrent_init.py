#!/usr/bin/env python3
"""Compare one pinned-C process-init callback race with the Rust coordinator."""

from __future__ import annotations

import argparse
import importlib.util
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


def parse_trace(output: str, language: str) -> dict[str, int]:
    begin = f"CRABC_MI_CONCURRENT_INIT_{language}_TRACE_BEGIN"
    end = f"CRABC_MI_CONCURRENT_INIT_{language}_TRACE_END"
    if output.count(begin) != 1 or output.count(end) != 1:
        raise ValueError(f"{language} concurrent-init trace has no single marked record")
    body = output.split(begin, 1)[1].split(end, 1)[0]
    fields: dict[str, int] = {}
    for line in body.splitlines():
        match = re.fullmatch(r"trace\.concurrent_init\.([a-z_]+)=([01])", line.strip())
        if match is None:
            if line.strip():
                raise ValueError(f"{language} concurrent-init trace contains an invalid field")
            continue
        if match[1] in fields:
            raise ValueError(f"{language} concurrent-init trace repeats {match[1]}")
        fields[match[1]] = int(match[2])
    if set(fields) != set(FIELDS):
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
    run.require_native_x86_64()
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
            "-pthread", "-o", str(c_binary),
        ]
        execute(c_command, cwd=source)
        c_record = parse_trace(execute([str(c_binary)], cwd=source, timeout=30), "C")
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
    return {
        "scope": "one post-attachment output callback, recursive owner, distinct once contender, and terminal owner",
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
    print(f"concurrent process initialization: {report['comparison']} ({len(FIELDS)} fields)")
    print(REPORT.relative_to(ROOT))


if __name__ == "__main__":
    main()
