#!/usr/bin/env python3
"""Execute the closed private x86 POSIX/ABI qualification-admission inventory.

This consumes real selected static crabc-libc artifacts.  It is deliberately
not the future dynamic os-test, libc-test, pthread-stress, signal-process, or
full ABI-inventory gate, and it cannot promote the x86 platform.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "qualification_posix_abi.json"
EXPECTED_SCHEMA = "crabc.x86_64-qualification-posix-abi-admission/v1"
EXPECTED_ID = "qualification-posix-abi-admission"
EXPECTED_TARGET = "Linux/x86-64 little-endian"
EXPECTED_CASES = (
    (
        "same-object-static-c-abi",
        "compat.abi-differential",
        "compat/x86_64/run_libc_same_object_static_c_abi_differential.sh",
        "x86 static C ABI same-object differential: PASS (libc.a; pinned musl 1.2.6)",
        1200,
    ),
    (
        "static-process-context",
        "compat.posix-process",
        "compat/x86_64/run_libc_process_context.sh",
        "x86 static crabc-libc process context: PASS",
        1200,
    ),
    (
        "static-signal-execution",
        "compat.posix-process",
        "compat/x86_64/run_libc_signal_execution.sh",
        "x86 static crabc-libc signal execution: PASS",
        1200,
    ),
    (
        "static-child-reaping",
        "compat.posix-process",
        "compat/x86_64/run_libc_child_reaping.sh",
        "x86 static libc child reaping: PASS",
        1200,
    ),
    (
        "static-pthread-tls-aggregate",
        "compat.posix-process",
        "compat/x86_64/run_libc_pthread_tls_aggregate.sh",
        "x86 static crabc-libc pthread/TLS aggregate: PASS",
        1200,
    ),
)


class ContractError(ValueError):
    """The checked-in admission inventory is incomplete or has drifted."""


class EvidenceError(RuntimeError):
    """A selected native child transaction did not satisfy its contract."""


@dataclass(frozen=True)
class Case:
    identifier: str
    family: str
    runner: Path
    expected_stdout_line: bytes
    timeout_seconds: int


def _exact_keys(value: dict[str, Any], expected: set[str], location: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = ", ".join(sorted(expected - actual)) or "none"
        unexpected = ", ".join(sorted(actual - expected)) or "none"
        raise ContractError(
            f"{location} keys drifted (missing: {missing}; unexpected: {unexpected})"
        )


def load_contract(path: Path = CONTRACT_PATH) -> tuple[Case, ...]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read qualification contract: {error}") from error
    if not isinstance(document, dict):
        raise ContractError("qualification contract must be an object")
    _exact_keys(document, {"schema", "id", "target", "cases"}, "contract")
    if document["schema"] != EXPECTED_SCHEMA:
        raise ContractError("qualification contract schema drifted")
    if document["id"] != EXPECTED_ID:
        raise ContractError("qualification contract id drifted")
    if document["target"] != EXPECTED_TARGET:
        raise ContractError("qualification target drifted")
    records = document["cases"]
    if not isinstance(records, list):
        raise ContractError("qualification cases must be an array")

    actual_records: list[tuple[str, str, str, str, int]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ContractError(f"cases[{index}] must be an object")
        _exact_keys(
            record,
            {
                "id",
                "family",
                "runner",
                "expected_stdout_line",
                "timeout_seconds",
            },
            f"cases[{index}]",
        )
        values = (
            record["id"],
            record["family"],
            record["runner"],
            record["expected_stdout_line"],
            record["timeout_seconds"],
        )
        if not all(isinstance(value, str) and value for value in values[:4]):
            raise ContractError(f"cases[{index}] has an empty non-string field")
        if not isinstance(values[4], int) or isinstance(values[4], bool):
            raise ContractError(f"cases[{index}] timeout must be an integer")
        actual_records.append(values)
    if tuple(actual_records) != EXPECTED_CASES:
        raise ContractError("qualification case roster or order drifted")

    cases: list[Case] = []
    for identifier, family, runner_text, marker, timeout_seconds in actual_records:
        runner = (ROOT / runner_text).resolve()
        try:
            runner.relative_to(ROOT)
        except ValueError as error:
            raise ContractError(f"case {identifier} runner escapes the repository") from error
        if runner.suffix != ".sh" or not runner.is_file():
            raise ContractError(f"case {identifier} runner is not a checked-in shell file")
        cases.append(
            Case(
                identifier=identifier,
                family=family,
                runner=runner,
                expected_stdout_line=marker.encode("utf-8"),
                timeout_seconds=timeout_seconds,
            )
        )
    return tuple(cases)


def validate_completed_process(
    case: Case, returncode: int, stdout: bytes, stderr: bytes
) -> None:
    if returncode != 0:
        raise EvidenceError(f"{case.identifier} exited {returncode}")
    nonempty_lines = [line for line in stdout.splitlines() if line]
    if nonempty_lines.count(case.expected_stdout_line) != 1:
        raise EvidenceError(
            f"{case.identifier} did not emit its unique completion marker"
        )
    if not nonempty_lines or nonempty_lines[-1] != case.expected_stdout_line:
        raise EvidenceError(
            f"{case.identifier} wrote output after its completion marker"
        )
    # Child gates own and validate their runtime streams.  Cargo and binutils
    # diagnostics from the build transaction remain visible here on failure;
    # they are not normalized or used as a success oracle.
    del stderr


def controlled_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "CC",
        "CFLAGS",
        "CPPFLAGS",
        "CXX",
        "CXXFLAGS",
        "LDFLAGS",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LIBRARY_PATH",
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "GCC_EXEC_PREFIX",
        "COMPILER_PATH",
        "CARGO_BUILD_TARGET",
        "CARGO_TARGET_DIR",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "MUSL_CC",
        "MUSL_ROOT",
    ):
        environment.pop(name, None)
    environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    return environment


def run_case(case: Case) -> None:
    process = subprocess.Popen(
        ["bash", str(case.runner)],
        cwd=ROOT,
        env=controlled_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=case.timeout_seconds)
    except subprocess.TimeoutExpired as error:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        if stdout:
            sys.stderr.buffer.write(stdout)
        if stderr:
            sys.stderr.buffer.write(stderr)
        raise EvidenceError(
            f"{case.identifier} timed out after {case.timeout_seconds}s"
        ) from error
    try:
        validate_completed_process(case, process.returncode, stdout, stderr)
    except EvidenceError:
        if stdout:
            sys.stderr.buffer.write(stdout)
        if stderr:
            sys.stderr.buffer.write(stderr)
        raise


def require_native_linux_x86_64() -> None:
    if platform.system() != "Linux":
        raise EvidenceError("qualification admission requires native Linux")
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        raise EvidenceError(
            f"qualification admission refuses emulation on {platform.machine()}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-contract",
        action="store_true",
        help="validate the closed inventory without executing native artifacts",
    )
    arguments = parser.parse_args()
    cases = load_contract()
    if arguments.check_contract:
        print(f"x86 qualification POSIX/ABI contract: PASS ({len(cases)} cases)")
        return 0

    require_native_linux_x86_64()
    for case in cases:
        run_case(case)
        print(f"x86 qualification POSIX/ABI admission: {case.identifier}: PASS")
    print(
        "x86 qualification POSIX/ABI admission: PASS "
        f"({len(cases)} selected artifact transactions; non-promoting)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ContractError, EvidenceError) as error:
        raise SystemExit(f"x86 qualification POSIX/ABI admission: ERROR: {error}") from error
