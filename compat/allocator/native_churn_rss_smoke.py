#!/usr/bin/env python3
"""Run the deterministic native-mimalloc selected-shadow churn/RSS smoke.

The fixture is intentionally standalone rather than another option in
``compat/allocator/run.py``.  Invoke this harness inside the canonical owned
loader boundary, after building the debug libc with ``native-mimalloc-shadow``:

    python3 scripts/run_owned_test_suite.py \
      --sysroot target/crabc-sysroot \
      --loader target/debug/libldso.so -- \
      python3 compat/allocator/native_churn_rss_smoke.py

It builds one C11 fixture through the installed ``crabc-cc`` driver.  The
fixture calls only standard production C allocation APIs, verifies one
cross-thread free while the source owner remains live, and then has the
initial thread free each worker-owned allocation after that worker has exited.
The report distinguishes observable RSS and workload liveness from allocator
metadata, which is deliberately not exposed through the production shadow C
ABI and therefore is never inferred from private test hooks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat/allocator/native-churn-rss-smoke-v3.5.0.json"
FIXTURE_SCHEMA = "crabc-mimalloc-native-churn-rss-smoke-fixture-v1"
REPORT_SCHEMA = "crabc-mimalloc-native-churn-rss-smoke-report-v1"
CANONICAL_LOADER = Path("/lib/ld-crabc-aarch64.so.1")
DEFAULT_REPORT = ROOT / "compat/reports/allocator/native-churn-rss-smoke-latest.json"
NEEDED_LIBRARY = re.compile(r"Shared library: \[(?P<name>[^]]+)\]")


class SmokeError(RuntimeError):
    """A violated selected-shadow evidence precondition or fixture result."""


def relative(path: Path) -> str:
    """Return a durable repository-relative spelling when possible."""

    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    """Hash one regular evidence input."""

    if not path.is_file():
        raise SmokeError(f"required input is not a regular file: {relative(path)}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Mapping[str, Any]:
    """Load one JSON object without silently accepting another shape."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SmokeError(f"could not read JSON object {relative(path)}: {error}") from error
    if not isinstance(value, dict):
        raise SmokeError(f"JSON root must be an object: {relative(path)}")
    return value


def require_string(value: Mapping[str, Any], key: str) -> str:
    """Read one required nonempty string field."""

    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise SmokeError(f"contract field {key!r} must be a nonempty string")
    return result


def require_positive_int(value: Mapping[str, Any], key: str) -> int:
    """Read one positive integer field without treating booleans as numbers."""

    result = value.get(key)
    if isinstance(result, bool) or not isinstance(result, int) or result <= 0:
        raise SmokeError(f"contract field {key!r} must be a positive integer")
    return result


def require_string_list(value: Mapping[str, Any], key: str) -> list[str]:
    """Read one list of nonempty strings."""

    result = value.get(key)
    if not isinstance(result, list) or not all(isinstance(item, str) and item for item in result):
        raise SmokeError(f"contract field {key!r} must be a list of nonempty strings")
    return list(result)


def validate_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the fixed native-shadow workload and its honest boundaries."""

    if contract.get("format") != 1 or contract.get("schema") != "crabc-mimalloc-native-churn-rss-smoke":
        raise SmokeError("unsupported native churn/RSS smoke contract")

    fixture = contract.get("fixture")
    execution = contract.get("execution")
    boundary = contract.get("production_shadow_boundary")
    observation = contract.get("state_observation")
    if not isinstance(fixture, dict) or not isinstance(execution, dict):
        raise SmokeError("contract must contain fixture and execution objects")
    if not isinstance(boundary, dict) or not isinstance(observation, dict):
        raise SmokeError("contract must contain production boundary and observation objects")

    fixture_path = ROOT / require_string(fixture, "path")
    if fixture_path != ROOT / "compat/allocator/native-churn-rss-smoke.c":
        raise SmokeError("fixture path changed from the reviewed native smoke source")
    fixture_sha256 = require_string(fixture, "sha256")
    if not re.fullmatch(r"[0-9a-f]{64}", fixture_sha256):
        raise SmokeError("fixture sha256 must be a lowercase SHA-256 digest")
    if sha256_file(fixture_path) != fixture_sha256:
        raise SmokeError("fixture source differs from the reviewed contract hash")
    if fixture.get("license") != "crabc-authored C11 evidence fixture":
        raise SmokeError("fixture provenance license changed")

    if execution.get("allocator_feature") != "native-mimalloc-shadow":
        raise SmokeError("execution must name the native-mimalloc shadow feature")
    if require_string(execution, "compiler") != "crabc-cc from CRABC_TEST_SYSROOT/bin":
        raise SmokeError("execution compiler boundary changed")
    if require_string(execution, "language") != "C11":
        raise SmokeError("execution language changed")
    if require_string(execution, "canonical_loader") != str(CANONICAL_LOADER):
        raise SmokeError("canonical loader boundary changed")
    if require_string_list(execution, "compile_flags") != [
        "-O2",
        "-DNDEBUG",
        "-fPIE",
        "-pie",
        "-ftls-model=initial-exec",
        "-pthread",
    ]:
        raise SmokeError("compile flags changed")
    if require_string_list(execution, "link_flags") != ["-Wl,--allow-shlib-undefined"]:
        raise SmokeError("link flags changed")
    if require_string_list(execution, "link_libraries") != ["-lc"]:
        raise SmokeError("link libraries changed")
    if require_string_list(execution, "expected_dynamic_dependencies") != ["libc.so"]:
        raise SmokeError("dynamic dependency boundary changed")
    for key in ("seed", "cycles", "process_epochs", "watchdog_seconds"):
        require_positive_int(execution, key)

    required_api = ["malloc", "free", "posix_memalign", "malloc_usable_size"]
    if require_string_list(boundary, "allowed_allocation_apis") != required_api:
        raise SmokeError("production allocation API boundary changed")
    if require_string_list(boundary, "forbidden_allocator_identifiers") != [
        "mi_",
        "libmimalloc",
        "native_allocate",
        "native_free",
        "__crabc_runtime",
    ]:
        raise SmokeError("forbidden allocator identifier boundary changed")
    if boundary.get("allocator_private_hooks") is not False:
        raise SmokeError("allocator private hook exclusion changed")
    if boundary.get("c_backend_fallback") is not False:
        raise SmokeError("C-backend fallback exclusion changed")

    if observation.get("rss") != "sampled-from-/proc/self/status-VmRSS":
        raise SmokeError("RSS observation method changed")
    if observation.get("allocator_metadata") != "not-exposed-by-production-shadow-c-api":
        raise SmokeError("allocator metadata boundary changed")
    if observation.get("metadata_high_water_bytes") is not None:
        raise SmokeError("metadata high-water must remain unavailable without a production API")

    source = fixture_path.read_text(encoding="utf-8")
    for identifier in boundary["forbidden_allocator_identifiers"]:
        if identifier in source:
            raise SmokeError(f"fixture contains forbidden allocator identifier: {identifier}")
    for identifier in required_api:
        if identifier not in source:
            raise SmokeError(f"fixture omits required production allocation API: {identifier}")
    required_semantics = [
        "owner_exits_with_live_blocks",
        "successful_cross_thread_handoffs",
        "post_exit_initial_thread_frees",
        "not-exposed-by-production-shadow-c-api",
    ]
    if any(marker not in source for marker in required_semantics):
        raise SmokeError("fixture no longer records the required legal-C lifecycle semantics")

    return {
        "fixture": fixture_path,
        "fixture_sha256": fixture_sha256,
        "seed": require_positive_int(execution, "seed"),
        "cycles": require_positive_int(execution, "cycles"),
        "process_epochs": require_positive_int(execution, "process_epochs"),
        "watchdog_seconds": require_positive_int(execution, "watchdog_seconds"),
        "compile_flags": require_string_list(execution, "compile_flags"),
        "link_flags": require_string_list(execution, "link_flags"),
        "link_libraries": require_string_list(execution, "link_libraries"),
    }


def command_record(command: Sequence[str], **kwargs: Any) -> dict[str, Any]:
    """Run one bounded command and retain output for a failure report."""

    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            **kwargs,
        )
    except subprocess.TimeoutExpired as error:
        return {
            "command": list(command),
            "status": None,
            "stdout": error.stdout or "",
            "stderr": error.stderr or "",
            "timed_out": True,
        }
    return {
        "command": list(command),
        "status": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "timed_out": False,
    }


def require_success(record: Mapping[str, Any], subject: str) -> None:
    """Raise an actionable error for a failed compile or execution record."""

    if record.get("timed_out"):
        raise SmokeError(f"{subject} exceeded the configured watchdog")
    if record.get("status") != 0:
        raise SmokeError(
            f"{subject} failed with status {record.get('status')}: "
            f"stdout={record.get('stdout')!r} stderr={record.get('stderr')!r}"
        )


def dynamic_dependencies(binary: Path) -> list[str]:
    """Read the exact NEEDED-library set of one selected-shadow fixture."""

    record = command_record(["readelf", "-d", str(binary)])
    require_success(record, "readelf dynamic dependency inspection")
    return NEEDED_LIBRARY.findall(str(record["stdout"]))


def require_owned_shadow_environment() -> tuple[Path, Path, Path]:
    """Require the launcher-staged owned sysroot, loader, and debug runtime."""

    raw_sysroot = os.environ.get("CRABC_TEST_SYSROOT")
    if not raw_sysroot:
        raise SmokeError(
            "native churn/RSS smoke requires CRABC_TEST_SYSROOT from scripts/run_owned_test_suite.py"
        )
    sysroot = Path(raw_sysroot).expanduser().resolve()
    compiler = sysroot / "bin/crabc-cc"
    manifest = sysroot / "share/crabc/manifest.json"
    runtime = ROOT / "target/debug"
    if not compiler.is_file() or not manifest.is_file():
        raise SmokeError("native churn/RSS smoke requires a complete owned crabc sysroot")
    if not (runtime / "libc.so").is_file() or not (runtime / "libldso.so").is_file():
        raise SmokeError("native churn/RSS smoke requires target/debug libc.so and libldso.so")
    if not CANONICAL_LOADER.is_file() or CANONICAL_LOADER.is_symlink():
        raise SmokeError(
            "native churn/RSS smoke must run under scripts/run_owned_test_suite.py canonical-loader staging"
        )
    return sysroot, compiler, runtime


def parse_fixture_output(
    stdout: str,
    *,
    seed: int,
    cycles: int,
) -> dict[str, Any]:
    """Validate one compact machine-readable fixture result."""

    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise SmokeError(f"fixture stdout is not one JSON result: {stdout!r}") from error
    if not isinstance(value, dict) or value.get("schema") != FIXTURE_SCHEMA:
        raise SmokeError("fixture JSON schema changed")
    expected = {
        "seed": seed,
        "cycles": cycles,
        "owner_exits_with_live_blocks": cycles,
        "successful_cross_thread_handoffs": cycles,
        "post_exit_initial_thread_frees": cycles * 6,
        "requested_bytes_live_final": 0,
        "usable_bytes_live_final": 0,
        "live_blocks_final": 0,
        "allocator_metadata_high_water_bytes": None,
        "allocator_metadata_observation": "not-exposed-by-production-shadow-c-api",
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise SmokeError(
                f"fixture result field {key!r} differs: expected {expected_value!r}, got {value.get(key)!r}"
            )
    positive_fields = [
        "requested_bytes_total",
        "requested_bytes_live_high_water",
        "usable_bytes_live_high_water",
        "live_blocks_high_water",
        "rss_samples",
    ]
    for key in positive_fields:
        result = value.get(key)
        if isinstance(result, bool) or not isinstance(result, int) or result <= 0:
            raise SmokeError(f"fixture result field {key!r} must be a positive integer")
    for key in ("rss_initial_bytes", "rss_final_bytes", "rss_high_water_bytes"):
        result = value.get(key)
        if isinstance(result, bool) or not isinstance(result, int) or result < 0:
            raise SmokeError(f"fixture result field {key!r} must be a nonnegative integer")
    if value["rss_high_water_bytes"] < max(value["rss_initial_bytes"], value["rss_final_bytes"]):
        raise SmokeError("fixture RSS high-water is below an observed RSS sample")
    return value


def run_smoke(
    contract: Mapping[str, Any],
    *,
    seed: int,
    cycles: int,
    epochs: int,
    watchdog_seconds: int,
) -> dict[str, Any]:
    """Build then run fresh selected-shadow fixture processes deterministically."""

    validated = validate_contract(contract)
    if min(seed, cycles, epochs, watchdog_seconds) <= 0:
        raise SmokeError("seed, cycles, epochs, and watchdog seconds must all be positive")
    _sysroot, compiler, runtime = require_owned_shadow_environment()
    fixture = validated["fixture"]
    assert isinstance(fixture, Path)

    with tempfile.TemporaryDirectory(prefix="crabc-native-churn-rss-smoke-") as temporary:
        artifact_root = Path(temporary)
        binary = artifact_root / "native-churn-rss-smoke"
        build_command = [
            str(compiler),
            "-std=c11",
            *validated["compile_flags"],
            "-L",
            str(runtime),
            str(fixture),
            *validated["link_flags"],
            *validated["link_libraries"],
            "-o",
            str(binary),
        ]
        build = command_record(build_command, cwd=ROOT)
        require_success(build, "native churn/RSS smoke fixture build")
        dependencies = dynamic_dependencies(binary)
        if dependencies != ["libc.so"]:
            raise SmokeError(
                "selected-shadow fixture dynamic dependency set differs from the production boundary: "
                f"{dependencies!r}"
            )
        environment = dict(os.environ)
        for key in ("LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"):
            environment.pop(key, None)
        environment["LD_LIBRARY_PATH"] = str(runtime)
        executions: list[dict[str, Any]] = []
        for epoch in range(epochs):
            epoch_seed = seed + epoch
            run_command = [str(binary), str(epoch_seed), str(cycles)]
            record = command_record(
                run_command,
                cwd=ROOT,
                env=environment,
                timeout=watchdog_seconds,
            )
            require_success(record, f"native churn/RSS smoke process epoch {epoch + 1}/{epochs}")
            if record["stderr"]:
                raise SmokeError(
                    f"fixture emitted unexpected stderr at epoch {epoch + 1}/{epochs}: {record['stderr']!r}"
                )
            fixture_result = parse_fixture_output(
                str(record["stdout"]), seed=epoch_seed, cycles=cycles
            )
            executions.append(
                {
                    "epoch": epoch + 1,
                    "seed": epoch_seed,
                    "fixture": fixture_result,
                    "watchdog": {"seconds": watchdog_seconds, "status": "passed"},
                }
            )
        return {
            "artifact": {
                "sha256": sha256_file(binary),
                "size_bytes": binary.stat().st_size,
            },
            "build": {
                "command": build_command,
                "dynamic_dependencies": dependencies,
            },
            "executions": executions,
        }


def high_water(executions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate observables without turning unavailable metadata into a proxy."""

    if not executions:
        raise SmokeError("no successful fixture executions to aggregate")
    fixture_results = [entry["fixture"] for entry in executions]
    if not all(isinstance(result, dict) for result in fixture_results):
        raise SmokeError("execution result shape changed")
    typed_results = [result for result in fixture_results if isinstance(result, dict)]
    return {
        "rss_bytes": max(result["rss_high_water_bytes"] for result in typed_results),
        "requested_live_bytes": max(
            result["requested_bytes_live_high_water"] for result in typed_results
        ),
        "usable_live_bytes": max(result["usable_bytes_live_high_water"] for result in typed_results),
        "live_blocks": max(result["live_blocks_high_water"] for result in typed_results),
        "allocator_metadata": {
            "available": False,
            "high_water_bytes": None,
            "reason": "not exposed by the production shadow C API",
        },
    }


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    """Publish one complete report without exposing a partial JSON document."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def report_for_success(
    contract: Mapping[str, Any],
    run: Mapping[str, Any],
    *,
    seed: int,
    cycles: int,
    epochs: int,
    watchdog_seconds: int,
) -> dict[str, Any]:
    """Create the durable report that a CI caller can consume directly."""

    executions = run.get("executions")
    if not isinstance(executions, list):
        raise SmokeError("successful run omitted execution records")
    return {
        "schema": REPORT_SCHEMA,
        "status": "passed",
        "contract": {
            "path": relative(CONTRACT_PATH),
            "sha256": sha256_file(CONTRACT_PATH),
            "fixture_sha256": contract["fixture"]["sha256"],
        },
        "configuration": {
            "seed": seed,
            "cycles_per_process": cycles,
            "fresh_process_epochs": epochs,
            "watchdog_seconds": watchdog_seconds,
        },
        "production_shadow_boundary": {
            "allocator_feature": "native-mimalloc-shadow",
            "allocation_apis": contract["production_shadow_boundary"]["allowed_allocation_apis"],
            "allocator_private_hooks": False,
            "c_backend_fallback": False,
            "dynamic_dependencies": run["build"]["dynamic_dependencies"],
        },
        "artifact": run["artifact"],
        "executions": executions,
        "high_water": high_water(executions),
    }


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the bounded, reproducible smoke controls."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, help="nonzero base seed (default: manifest)")
    parser.add_argument("--cycles", type=int, help="owner/handoff churn cycles per process")
    parser.add_argument("--epochs", type=int, help="fresh process epochs")
    parser.add_argument("--watchdog-seconds", type=int, help="per-process watchdog")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT, help="JSON report path")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the smoke and write a passed or failed machine-readable report."""

    args = parse_arguments(arguments)
    report_path = args.report.expanduser().resolve()
    try:
        contract = read_json(CONTRACT_PATH)
        validated = validate_contract(contract)
        seed = validated["seed"] if args.seed is None else args.seed
        cycles = validated["cycles"] if args.cycles is None else args.cycles
        epochs = validated["process_epochs"] if args.epochs is None else args.epochs
        watchdog_seconds = (
            validated["watchdog_seconds"]
            if args.watchdog_seconds is None
            else args.watchdog_seconds
        )
        run = run_smoke(
            contract,
            seed=seed,
            cycles=cycles,
            epochs=epochs,
            watchdog_seconds=watchdog_seconds,
        )
        report = report_for_success(
            contract,
            run,
            seed=seed,
            cycles=cycles,
            epochs=epochs,
            watchdog_seconds=watchdog_seconds,
        )
    except SmokeError as error:
        report = {
            "schema": REPORT_SCHEMA,
            "status": "failed",
            "contract": {"path": relative(CONTRACT_PATH)},
            "error": str(error),
        }
        atomic_write_json(report_path, report)
        print(f"native-churn-rss-smoke: {error}", file=sys.stderr)
        return 1
    atomic_write_json(report_path, report)
    print(json.dumps({"report": str(report_path), "status": "passed"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
