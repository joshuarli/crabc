#!/usr/bin/env python3
"""Validate executable x86 qualification declarations without claiming results.

``private_admission`` remains non-promoting. The eight ordered qualification
entries are planned or ready to execute; readiness pins cases and runners,
not a pre-existing success receipt. Actual qualification requires subsequent
source/tool/runtime/artifact-bound execution receipts outside tracked source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "compat" / "x86_64" / "qualification_manifest.json"
GENERATED_PATH = ROOT / "compat" / "x86_64" / "generated" / "qualification_manifest.json"
SCHEMA = "crabc.x86_64-qualification-manifest/v2"
CASE_SCHEMA = "crabc.x86_64-qualification-case-manifest/v1"
RECEIPT_SCHEMA = "crabc.x86_64-qualification-receipt/v1"
TARGET = {
    "triple": "x86_64-unknown-linux-musl",
    "system": "Linux",
    "machine": "x86_64",
    "endianness": "little",
}
EXECUTION_CONTRACT = {
    # Qualification case runners require the pinned native image.  The host
    # campaign runner may select only this dispatcher boundary; inside it,
    # cases receive the physical checkout-local work and temporary paths.
    "dispatcher_command": ["./scripts/dev-x86_64.sh", "qualification-manifest"],
    "work_directory": "/workspace/.work/x86_64",
    "temporary_directory": "/workspace/.work/x86_64/tmp",
    "oracle_compiler": "/usr/local/bin/crabc-x86_64-musl-gcc",
}
CHAIN = (
    "compat.abi-differential",
    "compat.posix-process",
    "compat.resolver-network",
    "compat.loader-corpus",
    "consumer.rust-std-lto",
    "consumer.source-build",
    "capability.accounting",
    "performance.release",
)
PRIVATE_ADMISSION = (
    (
        "posix-abi-admission",
        "compat/x86_64/qualification_posix_abi.json",
        "0afebd7ed94da8236d29a93c54b10dd6e9ea7519ca179ac61659d76d2c346446",
        ("python3", "compat/x86_64/run_qualification_posix_abi.py"),
    ),
)
GATE_CONTRACTS = (
    (
        "pinned-musl-1.2.6-and-frozen-linux-amd64-abi",
        "separate-pinned-musl-oracle-and-owned-crabc-candidate",
        "reject-ambient-target-crt-libc-loader-libgcc-compiler-rt-and-headers",
        "clean-native-linux-x86_64-worktree-and-scrubbed-environment",
        7200,
    ),
    (
        "pinned-musl-1.2.6-and-linux-5.10-process-abi",
        "separate-pinned-musl-oracle-and-owned-crabc-candidate",
        "reject-ambient-target-crt-libc-loader-libgcc-compiler-rt-and-headers",
        "clean-native-linux-x86_64-worktree-and-scrubbed-environment",
        7200,
    ),
    (
        "pinned-musl-1.2.6-and-controlled-linux-resolver-network",
        "separate-pinned-musl-oracle-and-owned-crabc-candidate",
        "reject-ambient-target-crt-libc-loader-libgcc-compiler-rt-and-headers",
        "clean-native-linux-x86_64-worktree-scrubbed-environment-and-controlled-network",
        7200,
    ),
    (
        "pinned-musl-1.2.6-and-frozen-loader-corpus",
        "separate-pinned-musl-oracle-and-owned-crabc-interpreter-and-libc",
        "reject-ambient-target-crt-libc-loader-libgcc-compiler-rt-and-headers",
        "clean-native-linux-x86_64-worktree-scrubbed-environment-and-materialized-sysroot",
        7200,
    ),
    (
        "frozen-aarch64-rust-std-lto-consumer-contract",
        "pinned-rust-toolchain-and-owned-crabc-runtime",
        "reject-ambient-target-crt-libc-loader-libgcc-compiler-rt-and-headers",
        "clean-native-linux-x86_64-worktree-scrubbed-environment-and-materialized-sysroot",
        7200,
    ),
    (
        "frozen-aarch64-selected-source-consumers-and-pinned-musl-1.2.6",
        "pinned-source-inputs-and-owned-crabc-sysroot",
        "reject-ambient-target-crt-libc-loader-libgcc-compiler-rt-and-headers",
        "clean-native-linux-x86_64-worktree-scrubbed-environment-and-materialized-sysroot",
        7200,
    ),
    (
        "immutable-aarch64-frozen-baseline-and-current-x86-ledger",
        "machine-validated-frozen-baseline-and-parity-ledger",
        "reject-unmapped-selected-private-or-artifact-only-progress",
        "clean-native-linux-x86_64-worktree-and-scrubbed-environment",
        1800,
    ),
    (
        "project-performance-contract-and-pinned-musl-1.2.6-comparison-lane",
        "controlled-native-x86_64-hardware-and-owned-crabc-runtime",
        "reject-ambient-target-crt-libc-loader-libgcc-compiler-rt-and-headers",
        "controlled-native-linux-x86_64-host-clean-worktree-and-scrubbed-environment",
        14400,
    ),
)
REQUIRED_GATE_FIELDS = {
    "id",
    "state",
    "oracle",
    "provenance",
    "purity",
    "isolation",
    "timeout_seconds",
}
READY_GATE_FIELDS = REQUIRED_GATE_FIELDS | {"case_manifest"}


class QualificationManifestError(ValueError):
    """A qualification declaration is incomplete, mutable, or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationManifestError(message)


def sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise QualificationManifestError(f"cannot hash {path}: {error}") from error


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def repository_file(value: object, location: str) -> tuple[str, Path]:
    require(isinstance(value, str) and value, f"{location} must be a nonempty path")
    relative = Path(value)
    require(not relative.is_absolute() and ".." not in relative.parts, f"{location} escapes the repository")
    resolved = (ROOT / relative).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as error:
        raise QualificationManifestError(f"{location} escapes the repository") from error
    require(resolved.is_file(), f"{location} does not name a checked-in file: {value}")
    return value, resolved


def exact_keys(value: Mapping[str, object], expected: set[str], location: str) -> None:
    actual = set(value)
    require(actual == expected, f"{location} keys drifted (missing: {sorted(expected - actual)}; unexpected: {sorted(actual - expected)})")


def nonempty_string(value: object, location: str) -> str:
    require(isinstance(value, str) and value, f"{location} must be a nonempty string")
    return value


def positive_timeout(value: object, location: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and value > 0, f"{location} must be a positive integer")
    return value


def load_json(path: Path, description: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise QualificationManifestError(f"cannot read {description}: {error}") from error
    require(isinstance(document, dict), f"{description} must be a JSON object")
    return document


def validated_command(value: object, location: str) -> tuple[str, ...]:
    require(isinstance(value, list) and value, f"{location} must be a nonempty argv array")
    command = tuple(nonempty_string(item, f"{location}[{index}]") for index, item in enumerate(value))
    require(command[0] in {"python3", "bash"}, f"{location} has an unapproved executable")
    require(len(command) == 2, f"{location} must select exactly one repository runner")
    _, runner = repository_file(command[1], f"{location}[1]")
    require(runner.suffix in {".py", ".sh"}, f"{location} runner has an invalid suffix")
    return command


def validate_private_admission(value: object) -> list[dict[str, object]]:
    require(isinstance(value, list), "private_admission must be an array")
    require(len(value) == len(PRIVATE_ADMISSION), "private admission roster drifted")
    result: list[dict[str, object]] = []
    for index, expected in enumerate(PRIVATE_ADMISSION):
        entry = value[index]
        require(isinstance(entry, Mapping), f"private_admission[{index}] must be an object")
        exact_keys(entry, {"id", "case_manifest", "case_manifest_sha256", "command", "non_promoting"}, f"private_admission[{index}]")
        identifier, manifest_path, manifest_hash, command = expected
        require(entry.get("id") == identifier, "private admission identifier or order drifted")
        declared_path, resolved = repository_file(entry.get("case_manifest"), f"private_admission[{index}].case_manifest")
        require(declared_path == manifest_path, "private admission case manifest path drifted")
        require(entry.get("case_manifest_sha256") == manifest_hash, "private admission case manifest hash drifted")
        require(sha256_file(resolved) == manifest_hash, "private admission case manifest bytes drifted")
        require(validated_command(entry.get("command"), f"private_admission[{index}].command") == command, "private admission command drifted")
        require(entry.get("non_promoting") is True, "private admission must be explicitly non-promoting")
        result.append({"id": identifier, "case_manifest": manifest_path, "case_manifest_sha256": manifest_hash, "command": list(command), "non_promoting": True})
    return result


def validate_ready_cases(gate: Mapping[str, object], location: str) -> dict[str, object]:
    case_reference = gate["case_manifest"]
    require(isinstance(case_reference, Mapping), f"{location}.case_manifest must be an object")
    exact_keys(case_reference, {"path", "sha256"}, f"{location}.case_manifest")
    case_path, case_file = repository_file(case_reference.get("path"), f"{location}.case_manifest.path")
    case_hash = nonempty_string(case_reference.get("sha256"), f"{location}.case_manifest.sha256")
    require(sha256_file(case_file) == case_hash, f"{location} case manifest hash does not match immutable bytes")
    case = load_json(case_file, f"{location} case manifest")
    exact_keys(case, {"schema", "gate", "target", "oracle", "provenance", "purity", "isolation", "cases"}, f"{location} case manifest")
    require(case.get("schema") == CASE_SCHEMA, f"{location} case manifest schema drifted")
    require(case.get("gate") == gate["id"], f"{location} case manifest names the wrong gate")
    require(case.get("target") == TARGET, f"{location} case manifest target is not native x86_64 musl")
    for field in ("oracle", "provenance", "purity", "isolation"):
        require(case.get(field) == gate[field], f"{location} case manifest {field} drifted")
    cases = case.get("cases")
    require(isinstance(cases, list) and cases, f"{location} case manifest has no cases")
    case_ids: set[str] = set()
    for case_index, item in enumerate(cases):
        require(isinstance(item, Mapping), f"{location} case manifest cases[{case_index}] must be an object")
        exact_keys(
            item,
            {"id", "command", "runner_sha256", "expected_stdout_line", "timeout_seconds"},
            f"{location} case manifest cases[{case_index}]",
        )
        case_id = nonempty_string(item.get("id"), f"{location} case manifest cases[{case_index}].id")
        require(case_id not in case_ids, f"{location} case manifest duplicates case {case_id}")
        case_ids.add(case_id)
        command = validated_command(
            item.get("command"), f"{location} case manifest cases[{case_index}].command"
        )
        _, runner = repository_file(
            command[1], f"{location} case manifest cases[{case_index}].command[1]"
        )
        runner_hash = nonempty_string(
            item.get("runner_sha256"), f"{location} case manifest cases[{case_index}].runner_sha256"
        )
        require(
            sha256_file(runner) == runner_hash,
            f"{location} case manifest cases[{case_index}] runner hash does not match immutable bytes",
        )
        nonempty_string(item.get("expected_stdout_line"), f"{location} case manifest cases[{case_index}].expected_stdout_line")
        timeout = positive_timeout(item.get("timeout_seconds"), f"{location} case manifest cases[{case_index}].timeout_seconds")
        require(timeout <= gate["timeout_seconds"], f"{location} case manifest case timeout exceeds its gate timeout")
    return {"case_manifest": case_path, "case_manifest_sha256": case_hash, "case_count": len(cases)}


def validate_contract(document: Mapping[str, object]) -> dict[str, object]:
    exact_keys(document, {"schema", "id", "target", "policy", "execution", "private_admission", "promotion_chain"}, "qualification contract")
    require(document.get("schema") == SCHEMA, "qualification contract schema drifted")
    require(document.get("id") == "x86_64-native-qualification", "qualification contract id drifted")
    require(document.get("target") == TARGET, "qualification contract target drifted")
    policy = document.get("policy")
    require(isinstance(policy, Mapping), "qualification policy must be an object")
    exact_keys(policy, {"public_support", "promotion_ready", "native_execution_only"}, "qualification policy")
    require(policy == {"public_support": False, "promotion_ready": False, "native_execution_only": True}, "qualification policy may not assert promotion or public support")
    require(
        document.get("execution") == EXECUTION_CONTRACT,
        "qualification execution boundary drifted",
    )
    admission = validate_private_admission(document.get("private_admission"))
    gates = document.get("promotion_chain")
    require(isinstance(gates, list) and len(gates) == len(CHAIN), "qualification promotion chain roster drifted")
    normalized: list[dict[str, object]] = []
    incomplete: list[str] = []
    ready_count = 0
    runnable_prefix: list[str] = []
    prefix_open = True
    for index, gate in enumerate(gates):
        location = f"promotion_chain[{index}]"
        require(isinstance(gate, Mapping), f"{location} must be an object")
        identifier = CHAIN[index]
        expected_oracle, expected_provenance, expected_purity, expected_isolation, expected_timeout = GATE_CONTRACTS[index]
        state = gate.get("state")
        require(gate.get("id") == identifier, "qualification promotion chain order drifted")
        require(state in {"planned", "ready"}, f"{location}.state must be planned or ready; declarations cannot claim completion")
        exact_keys(gate, REQUIRED_GATE_FIELDS if state == "planned" else READY_GATE_FIELDS, location)
        fields = {field: nonempty_string(gate.get(field), f"{location}.{field}") for field in ("oracle", "provenance", "purity", "isolation")}
        timeout = positive_timeout(gate.get("timeout_seconds"), f"{location}.timeout_seconds")
        require(
            (fields["oracle"], fields["provenance"], fields["purity"], fields["isolation"], timeout)
            == (expected_oracle, expected_provenance, expected_purity, expected_isolation, expected_timeout),
            f"{location} oracle, provenance, purity, isolation, or timeout contract drifted",
        )
        row: dict[str, object] = {"id": identifier, "state": state, **fields, "timeout_seconds": timeout}
        row["depends_on"] = list(CHAIN[:index])
        incomplete.append(identifier)
        if state == "planned":
            prefix_open = False
        else:
            row.update(validate_ready_cases(gate, location))
            ready_count += 1
            if prefix_open:
                runnable_prefix.append(identifier)
        normalized.append(row)
    require(not set(item["id"] for item in admission) & set(CHAIN), "private admission cannot be a promotion gate")
    return {"schema": SCHEMA, "contract_sha256": sha256_file(CONTRACT_PATH), "target": TARGET, "policy": dict(policy), "execution": dict(EXECUTION_CONTRACT), "private_admission": admission, "promotion_chain": normalized, "completed_gate_count": 0, "ready_gate_count": ready_count, "runnable_prefix": runnable_prefix, "incomplete_gates": incomplete, "promotion_ready": False}


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, object]:
    return validate_contract(load_json(path, "qualification contract"))


def write_or_check(path: Path, report: Mapping[str, object], check: bool) -> None:
    expected = canonical_json(report)
    if check:
        try:
            actual = path.read_bytes()
        except OSError as error:
            raise QualificationManifestError(f"generated qualification manifest is missing: {error}") from error
        require(actual == expected, "generated qualification manifest is stale")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(expected)


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="require the checked-in generated manifest to be current")
    parser.add_argument("--output", type=Path, default=GENERATED_PATH, help="generated JSON destination")
    parser.add_argument("--stdout", action="store_true", help="write canonical generated JSON to stdout")
    parsed = parser.parse_args(arguments)
    require(not (parsed.check and parsed.stdout), "--check and --stdout cannot be combined")
    report = load_contract()
    if parsed.stdout:
        print(canonical_json(report).decode("utf-8"), end="")
    else:
        write_or_check(parsed.output, report, parsed.check)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except QualificationManifestError as error:
        raise SystemExit(f"x86 qualification manifest: ERROR: {error}") from error
