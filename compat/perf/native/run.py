#!/usr/bin/env python3
"""Run repeatable Rustybench facade comparisons for crabc-rs and Rustix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA = 1
BACKENDS = ("crabc", "rustix")


class RunnerError(Exception):
    """A setup error that should leave a complete unsupported report."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def comparison_source(root: Path, environment_name: str, directory_name: str) -> Path:
    """Resolve an explicit Docker mount or the conventional host sibling."""

    return Path(os.environ.get(environment_name, root.parent / directory_name)).expanduser().resolve()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=5, help="complete Rustybench invocations per backend")
    parser.add_argument("--sample-count", type=int, default=100, help="Rustybench timed samples per invocation")
    parser.add_argument(
        "--sample-size",
        type=int,
        default=1000,
        help="Rustybench iterations per timed sample; batch fast syscalls above timer granularity",
    )
    parser.add_argument("--label", default="baseline", help="report label (default: %(default)s)")
    parser.add_argument("--report", type=Path, default=None, help="output JSON path")
    parser.add_argument(
        "--build-std",
        action="store_true",
        help="rebuild std and panic_abort with the fixture's selected bench profile",
    )
    return parser.parse_args()


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(command: list[str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    return result.stdout


def check_inputs(args: argparse.Namespace, root: Path) -> None:
    if sys.platform != "linux" or platform.machine() != "aarch64":
        raise RunnerError(f"requires native Linux/AArch64; found {sys.platform}/{platform.machine()}")
    if args.runs <= 0 or args.sample_count <= 0 or args.sample_size <= 0:
        raise RunnerError("--runs, --sample-count, and --sample-size must be positive")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.label):
        raise RunnerError("--label may contain only letters, digits, dot, underscore, and dash")
    for path in (
        root / "compat/perf/native/Cargo.toml",
        comparison_source(root, "CRABC_RUSTYBENCH_SOURCE", "rustybench") / "Cargo.toml",
        comparison_source(root, "CRABC_NATIVE_RUSTIX_SOURCE", "rustix") / "Cargo.toml",
    ):
        if not path.is_file():
            raise RunnerError(f"required local comparison source is missing: {path}")
    if shutil.which("cargo") is None:
        raise RunnerError("cargo is unavailable")


def median(values: list[int]) -> int:
    return round(statistics.median(values))


def aggregate_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Median complete invocations, retaining every Rustybench JSON result."""

    by_name: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        for benchmark in run["benchmarks"]:
            by_name.setdefault(benchmark["name"], []).append(benchmark)
    result: dict[str, Any] = {}
    for name, benchmarks in sorted(by_name.items()):
        if len(benchmarks) != len(runs):
            raise RunnerError(f"benchmark {name!r} was absent from one or more Rustybench runs")
        resources = [item.get("process_resources") for item in benchmarks]
        if any(item is None for item in resources):
            raise RunnerError(f"benchmark {name!r} lacks Rustybench process_resources")
        result[name] = {
            "invocation_count": len(benchmarks),
            "median_ns": median([item["median_ns"] for item in benchmarks]),
            "alloc_count": median([item["alloc_count"] for item in benchmarks]),
            "alloc_bytes": median([item["alloc_bytes"] for item in benchmarks]),
            "max_alloc_count": median([item["max_alloc_count"] for item in benchmarks]),
            "max_alloc_bytes": median([item["max_alloc_bytes"] for item in benchmarks]),
            "process_resources": {
                "status": resources[0]["status"],
                "memory_status": resources[0]["memory_status"],
                **{
                    key: median([item[key] for item in resources if item[key] is not None])
                    if all(item[key] is not None for item in resources)
                    else None
                    for key in (
                        "user_cpu_ns",
                        "system_cpu_ns",
                        "voluntary_context_switches",
                        "involuntary_context_switches",
                        "minor_page_faults",
                        "major_page_faults",
                        "rss_bytes",
                        "pss_bytes",
                    )
                },
            },
        }
    return result


def run_backend(root: Path, args: argparse.Namespace, backend: str) -> dict[str, Any]:
    manifest = root / "compat/perf/native/Cargo.toml"
    # Build from a disposable cwd so the repository's `.cargo/config.toml`
    # cannot inject its symbol-accounting `link-dead-code` flag. An explicit
    # empty encoded flag set overrides inherited Rust flags without changing
    # Cargo's native AArch64/musl host-linker selection.
    environment = dict(os.environ)
    environment.pop("RUSTFLAGS", None)
    environment["CARGO_ENCODED_RUSTFLAGS"] = ""
    environment["CARGO_TARGET_DIR"] = str(
        root / "target" / ("perf-native-build-std-clang" if args.build_std else "perf-native-stock-std")
    )
    command = ["cargo"]
    if args.build_std:
        # Cargo's benchmark harness requires an unwind-capable std. This is
        # the user-requested empty build-std feature experiment. The fixture
        # deliberately has no bench-profile panic override: Cargo otherwise
        # builds incompatible `core` units for Rustybench's proc-macro graph.
        # The existing application proof retains its separate `panic_abort`
        # closure.
        command.extend(["-Z", "build-std=std", "-Z", "build-std-features="])
    command.extend([
        "bench", "--manifest-path", str(manifest), "--bench", "native", "--no-default-features",
        "--features", backend, "--", "--format", "json", "--sample-count",
        str(args.sample_count), "--sample-size", str(args.sample_size),
    ])
    observations: list[dict[str, Any]] = []
    isolated_cwd = Path(tempfile.mkdtemp(prefix="crabc-perf-native-", dir="/tmp"))
    try:
        for index in range(args.runs):
            result = subprocess.run(command, cwd=isolated_cwd, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if result.returncode != 0:
                raise RunnerError(
                    f"{backend} Rustybench run {index} failed ({result.returncode}): "
                    + result.stderr[:8192].decode("utf-8", errors="replace")
                )
            try:
                observation = json.loads(result.stdout)
            except json.JSONDecodeError as error:
                raise RunnerError(
                    f"{backend} Rustybench run {index} did not emit one JSON report: "
                    + result.stdout[:1024].decode("utf-8", errors="replace")
                    + " stderr: "
                    + result.stderr[:2048].decode("utf-8", errors="replace")
                ) from error
            if observation.get("schema") != 1 or not isinstance(observation.get("benchmarks"), list):
                raise RunnerError(f"{backend} Rustybench run {index} violated the schema-1 report contract")
            observations.append(observation)
    finally:
        shutil.rmtree(isolated_cwd, ignore_errors=True)
    return {
        "status": "ok",
        "command": command,
        "rustflags": environment["CARGO_ENCODED_RUSTFLAGS"],
        "runs": observations,
        "summary": aggregate_runs(observations),
    }


def main() -> int:
    args = parse_args()
    root = repository_root()
    report_path = args.report or root / "compat/reports/perf" / f"native-{args.label}.json"
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "kind": "crabc-rs-rustix-performance",
        "label": args.label,
        "status": "ok",
        "measurement_contract": {
            "comparison": "identical Rustybench fixture and inputs; only the direct facade feature varies",
            "timing": "Rustybench timed sample medians, repeated across independent cargo-bench invocations",
            "resources": "Rustybench Linux getrusage deltas and post-sample procfs RSS/PSS snapshots",
            "allocations": "Rustybench AllocProfiler for Rust-process allocations; not a C allocator measurement",
            "syscalls": "use Rustybench's separate diagnostic command; never infer timing from its strace output",
        },
        "host": {"system": platform.system(), "machine": platform.machine(), "release": platform.release()},
        "inputs": {
            "fixture_sha256": sha256_file(root / "compat/perf/native/src/main.rs"),
            "crabc_rs_cargo_sha256": sha256_file(root / "crabc-rs/Cargo.toml"),
            "rustix_cargo_sha256": None,
            "rustybench_cargo_sha256": None,
            "rustc_version": command_output(["rustc", "--version"], root).splitlines()[:1],
            "runs": args.runs,
            "sample_count": args.sample_count,
            "sample_size": args.sample_size,
            "build_std": args.build_std,
        },
        "backends": {},
    }
    try:
        check_inputs(args, root)
        report["inputs"]["rustix_cargo_sha256"] = sha256_file(
            comparison_source(root, "CRABC_NATIVE_RUSTIX_SOURCE", "rustix") / "Cargo.toml"
        )
        report["inputs"]["rustybench_cargo_sha256"] = sha256_file(
            comparison_source(root, "CRABC_RUSTYBENCH_SOURCE", "rustybench") / "Cargo.toml"
        )
        for backend in BACKENDS:
            report["backends"][backend] = run_backend(root, args, backend)
    except RunnerError as error:
        report["status"] = "unsupported" if not report["backends"] else "partial"
        report["error"] = str(error)
    atomic_write_json(report_path, report)
    print(report_path)
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
