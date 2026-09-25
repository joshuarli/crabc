#!/usr/bin/env python3
"""Compare warmed owner-local allocation traces at the native boundary.

The pinned mimalloc v3.5.0 C driver (``native_local_trace_x86_64.c``) and the
Rust test ``native_local_trace::emit_native_local_trace`` apply the same
generated workloads, each in a fresh process, first on the initial owner and
then on one later worker owner: C through ``mi_malloc_aligned(size, 16)``,
``mi_zalloc_aligned`` and ``mi_free`` on the default Theap, Rust through the
production ``native_allocate_aligned(size, 16, zero)`` / ``native_free``
entries. After every operation both print the touched page (by discovery
order, blocks by index) with its used/capacity/list heads/retirement countdown and the
default Theap's queue count, page count, generic-administration counters and
retired bounds. The traces must match line by line.

The workloads stay below page capacity, so the default abandoning Theap never
reaches abandonment. This is private native Linux/x86-64 allocator evidence;
it claims no remote-free, abandonment, reclaim, public ``mi_*``, libc
integration, backend promotion, or AArch64 behavior.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "compat/allocator/run.py"
C_DRIVER_PATH = ROOT / "compat/allocator/native_local_trace_x86_64.c"
TARGET = "x86_64-unknown-linux-musl"
RUST_TRACE_TEST = "native_local_trace::emit_native_local_trace"
WORKLOAD_ENV = "CRABC_NATIVE_LOCAL_TRACE_WORKLOAD"
OUTPUT_ENV = "CRABC_NATIVE_LOCAL_TRACE_OUTPUT"
WORKLOAD_MAGIC = "native-local-trace 1"
COMPILE_DEFINITIONS = ("-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1")
RELEASE_SOURCE_SET = (
    "src/alloc.c", "src/alloc-aligned.c", "src/alloc-posix.c", "src/arena.c", "src/bitmap.c",
    "src/heap.c", "src/init.c", "src/libc.c", "src/options.c", "src/os.c", "src/page.c",
    "src/page-map.c", "src/random.c", "src/stats.c", "src/subproc.c", "src/theap.c",
    "src/threadlocal.c", "src/prim/prim.c", "src/prim/prim-tls.c",
)
SMALL_SIZES = (8, 16, 24, 32, 48, 64, 96, 128, 256, 512, 1000, 1024)

spec = importlib.util.spec_from_file_location("crabc_allocator_run", RUNNER_PATH)
assert spec is not None and spec.loader is not None
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

REPORT_PATH = run.REPORT_ROOT / "x86_64/native-local-trace-latest.json"


class TraceError(RuntimeError):
    """The differential could not run or its traces diverged."""


class Workload:
    def __init__(self) -> None:
        self.lines = [WORKLOAD_MAGIC]
        self.next_id = 0
        self.live: list[int] = []

    def allocate(self, size: int, zero: bool = False) -> int:
        identifier = self.next_id
        self.next_id += 1
        self.lines.append(f"a {identifier} {size} {int(zero)}")
        self.live.append(identifier)
        return identifier

    def free(self, identifier: int) -> None:
        self.live.remove(identifier)
        self.lines.append(f"f {identifier}")

    def text(self) -> str:
        if self.live:
            raise TraceError("a generated workload leaves live blocks")
        return "\n".join(self.lines) + "\n"


def warmed_pairs() -> str:
    """Repeated allocate/free pairs: every steady call is a fast path, and the
    single-size run crosses the 1000-call generic administration step."""
    workload = Workload()
    for size in SMALL_SIZES:
        for _ in range(16):
            workload.free(workload.allocate(size))
    for _ in range(2100):
        workload.free(workload.allocate(64))
    return workload.text()


def batches() -> str:
    """LIFO, FIFO, and interleaved frees, reuse after retirement, and zeroing."""
    workload = Workload()
    for size in (16, 64, 256, 1024):
        ids = [workload.allocate(size) for _ in range(40)]
        for identifier in reversed(ids[20:]):
            workload.free(identifier)
        ids = ids[:20] + [workload.allocate(size, zero=True) for _ in range(10)]
        for identifier in ids[::2]:
            workload.free(identifier)
        for identifier in ids[1::2]:
            workload.free(identifier)
        for _ in range(4):
            workload.free(workload.allocate(size, zero=True))
    return workload.text()


def random_mix(seed: int, steps: int) -> str:
    """A seeded mix whose live set stays far below any page's capacity."""
    generator = random.Random(seed)
    workload = Workload()
    for _ in range(steps):
        if workload.live and (len(workload.live) >= 24 or generator.random() < 0.45):
            workload.free(generator.choice(workload.live))
        else:
            workload.allocate(generator.choice(SMALL_SIZES), zero=generator.random() < 0.2)
    for identifier in list(workload.live):
        workload.free(identifier)
    return workload.text()


def workloads() -> dict[str, str]:
    return {
        "warmed-pairs": warmed_pairs(),
        "batches": batches(),
        "random-mix-1": random_mix(0x5EED01, 6000),
        "random-mix-2": random_mix(0x5EED02, 6000),
    }


def clean_environment() -> dict[str, str]:
    return {name: value for name, value in os.environ.items() if not name.lower().startswith("mimalloc_")}


def build_c_driver(work: Path, offline: bool) -> Path:
    pin = run.load_pin()
    archive = run.fetch_archive(pin, offline)
    source = run.safe_extract(archive, work / "source", pin["archive_root"])
    binary = work / "native-local-trace-c"
    command = [
        run.require_tool("musl-gcc"), "-std=c11", "-fPIC", "-ftls-model=initial-exec",
        *COMPILE_DEFINITIONS, "-I", str(source / "include"), "-I", str(source / "src"),
        *run.CONFIGURATION_PROFILES["release"], str(C_DRIVER_PATH),
        *(str(source / member) for member in RELEASE_SOURCE_SET), "-pthread", "-o", str(binary),
    ]
    run.require_success(run.command_record(command, cwd=source, timeout_seconds=600), "pinned C native local-trace driver build")
    return binary


def rust_test_binary() -> Path:
    command = [
        "cargo", "test", "--locked", "--target", TARGET, "-p", "crabc-mimalloc", "--lib",
        "--no-default-features", "--no-run", "--message-format=json",
    ]
    record = run.command_record(command, cwd=ROOT, timeout_seconds=3600)
    run.require_success(record, "Rust native local-trace test build")
    executables = []
    for line in str(record["stdout"]).splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            message.get("reason") == "compiler-artifact"
            and message.get("target", {}).get("name") == "crabc_mimalloc"
            and message.get("profile", {}).get("test")
            and message.get("executable")
        ):
            executables.append(message["executable"])
    if len(executables) != 1:
        raise TraceError(f"expected one crabc-mimalloc unit test executable, found {executables}")
    return Path(executables[0])


def first_divergence(c_lines: Sequence[str], rust_lines: Sequence[str]) -> dict[str, Any] | None:
    for index, (c_line, rust_line) in enumerate(zip(c_lines, rust_lines)):
        if c_line != rust_line:
            return {"line": index + 1, "pinned_c": c_line, "rust": rust_line,
                    "context": list(c_lines[max(0, index - 3):index])}
    if len(c_lines) != len(rust_lines):
        return {"line": min(len(c_lines), len(rust_lines)) + 1, "pinned_c_lines": len(c_lines),
                "rust_lines": len(rust_lines)}
    return None


def profile_section(lines: Sequence[str], profile: str | None) -> list[str]:
    """The lines of one ``profile`` block, or every line when ``None``."""
    if profile is None:
        return list(lines)
    selected: list[str] = []
    current = None
    for line in lines:
        if line.startswith("profile "):
            current = line.split()[1]
        if current == profile:
            selected.append(line)
    return selected


def run_differential(offline: bool, profile: str | None = None) -> dict[str, Any]:
    run.require_native_x86_64()
    with tempfile.TemporaryDirectory(prefix="crabc-native-local-trace-", dir=os.environ.get("TMPDIR")) as name:
        work = Path(name)
        c_binary = build_c_driver(work, offline)
        rust_binary = rust_test_binary()
        results: dict[str, Any] = {}
        for label, text in workloads().items():
            workload = work / f"{label}.workload"
            workload.write_text(text, encoding="utf-8")
            c_output, rust_output = work / f"{label}.c.trace", work / f"{label}.rust.trace"
            record = run.command_record((str(c_binary), str(workload), str(c_output)), cwd=work,
                                        env=clean_environment(), timeout_seconds=1800)
            run.require_success(record, f"pinned C native local trace for {label}")
            environment = clean_environment()
            environment[WORKLOAD_ENV], environment[OUTPUT_ENV] = str(workload), str(rust_output)
            record = run.command_record(
                (str(rust_binary), RUST_TRACE_TEST, "--exact", "--nocapture", "--test-threads=1"),
                cwd=ROOT, env=environment, timeout_seconds=1800)
            run.require_success(record, f"Rust native local trace for {label}")
            if run.parse_rust_test_count(str(record["stdout"]) + "\n" + str(record["stderr"])) != 1:
                raise TraceError(f"Rust native local trace for {label} did not run exactly one test")
            c_lines = profile_section(c_output.read_text(encoding="utf-8").splitlines(), profile)
            rust_lines = profile_section(rust_output.read_text(encoding="utf-8").splitlines(), profile)
            profile_divergences: dict[str, int] = {}
            section = "-"
            for c_line, rust_line in zip(c_lines, rust_lines):
                if c_line.startswith("profile "):
                    section = c_line.split()[1]
                if c_line != rust_line:
                    profile_divergences[section] = profile_divergences.get(section, 0) + 1
            results[label] = {
                "operations": text.count("\n") - 1,
                "trace_lines": len(c_lines),
                "divergence": first_divergence(c_lines, rust_lines),
                "divergent_lines_by_profile": profile_divergences,
            }
    report = {
        "kind": "crabc-mimalloc-x86_64-native-local-trace",
        "schema": 1,
        "profiles": [profile] if profile is not None else ["initial", "worker"],
        "workloads": results,
        "status": "pass" if all(result["divergence"] is None for result in results.values()) else "fail",
    }
    run.write_json(REPORT_PATH, report)
    return report


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--offline", action="store_true", help="require the verified source archive to be cached")
    parser.add_argument("--profile", choices=("initial", "worker"), default=None,
                        help="compare only this owner's trace block (default: both)")
    options = parser.parse_args(arguments)
    try:
        report = run_differential(options.offline, options.profile)
    except (TraceError, run.HarnessError, OSError) as error:
        print(f"allocator x86-64 native local trace: FAIL: {error}", file=sys.stderr)
        return 1
    for label, result in report["workloads"].items():
        if result["divergence"] is not None:
            print(f"allocator x86-64 native local trace: {label} diverges "
                  f"({json.dumps(result['divergent_lines_by_profile'])} lines): {json.dumps(result['divergence'])}",
                  file=sys.stderr)
    if report["status"] != "pass":
        print(f"allocator x86-64 native local trace: FAIL ({REPORT_PATH})", file=sys.stderr)
        return 1
    lines = sum(result["trace_lines"] for result in report["workloads"].values())
    print(f"allocator x86-64 native local trace: PASS ({len(report['workloads'])} workloads, {lines} matched lines; {REPORT_PATH})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
