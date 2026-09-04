#!/usr/bin/env python3
"""Run a deliberately bounded native Linux/x86-64 fault-injection lane.

This judge executes five named crate-private ``crabc-mimalloc`` regressions
whose injected failures preserve a specifically named mapping-state owner or
retry state.  It is intentionally independent of ``run.py``: that runner
owns the AArch64 production-oracle contract, while this file records a narrow
native x86-64 laboratory result without promoting x86 libc, loader,
``crabc-rs``, public ``mi_*``, or allocator-backend support.

The lane fails closed on the canonical dispatcher provenance.  An x86-64
Docker guest alone is insufficient because it can be QEMU-emulated; the
dispatcher must attest a native x86-64 host through ``CRABC_EXECUTION_MODE``
and ``CRABC_HOST_ARCH``.  Every Cargo invocation fixes the musl target, uses
``--locked``, runs one exact named test serially, and writes to a disposable
target directory outside the workspace.

This is not a general fault-injection or invalid-program/misuse parity claim.
It records only the selected in-process fault plans and the state-preservation
assertions already present in their named Rust regressions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-musl"
REPORT = ROOT / "compat/reports/allocator/x86_64/fault-injection.json"
LOCKFILE = ROOT / "Cargo.lock"

TEST_RESULT = re.compile(
    r"test result: (?P<status>ok|FAILED)\. "
    r"(?P<passed>\d+) passed; (?P<failed>\d+) failed; "
    r"(?P<ignored>\d+) ignored; (?P<measured>\d+) measured; "
    r"(?P<filtered>\d+) filtered out;"
)
RUSTC_HOST = re.compile(r"^host: (?P<target>\S+)$", re.MULTILINE)


class EvidenceError(RuntimeError):
    """A failed evidence precondition or selected failure-path regression."""


@dataclass(frozen=True)
class FaultLane:
    """One fixed, source-named failure-path regression.

    The fault-point names are the exact ``crate::os::fault::Point`` variants
    reached by the test's injected plan.  They are documentation of a narrow
    selected path, not a declaration that every operation at that point is
    covered.
    """

    identifier: str
    test_filter: str
    fault_points: tuple[str, ...]
    expected_pass_count: int
    state_preservation: tuple[str, ...]


# These lanes are deliberately named rather than discovered.  A newly added
# source test cannot silently broaden the report: a reviewer must add its
# exact filter, fault points, and retained-state assertion here first.
TEST_LANES = (
    FaultLane(
        identifier="native-mapping-commit-selected-ordinal",
        test_filter="os::tests::fault_injection_fails_the_selected_ordinal_without_a_hidden_retry",
        fault_points=("Commit",),
        expected_pass_count=1,
        state_preservation=(
            "the selected second mapping operation fails at commit without a hidden retry or fallback",
            "the failed commit leaves the reserved native mapping owned so its explicit unmap succeeds",
        ),
    ),
    FaultLane(
        identifier="metadata-map-commit-retry",
        test_filter="meta::tests::map_and_commit_failure_leave_the_owner_retryable_without_private_backing",
        fault_points=("Map", "Commit"),
        expected_pass_count=1,
        state_preservation=(
            "map and commit failures leave the static metadata owner cold and unpublished",
            "after injected failure is disabled, a fresh metadata allocation and release succeed",
        ),
    ),
    FaultLane(
        identifier="aligned-claim-unmap-retry",
        test_filter="os_page::tests::failed_unpublished_release_retains_one_claim_for_retry",
        fault_points=("Unmap",),
        expected_pass_count=1,
        state_preservation=(
            "an injected unpublished unmap failure retains exactly one claim owner",
            "the retained claim can be released after the selected fault is disabled",
        ),
    ),
    FaultLane(
        identifier="aligned-claim-commit-unmap-retention",
        test_filter="os_page::tests::commit_failure_with_failed_cleanup_transfers_the_live_claim_owner",
        fault_points=("Commit", "Unmap"),
        expected_pass_count=1,
        state_preservation=(
            "a metadata-commit failure paired with cleanup-unmap failure transfers a live claim owner",
            "the failure path cannot publish a page and the retained claim releases after fault removal",
        ),
    ),
    FaultLane(
        identifier="external-arena-decommit-retry-state",
        test_filter="single_thread::tests::forced_unpinned_arena_decommit_failure_keeps_retry_state_and_external_mapping",
        fault_points=("Decommit",),
        expected_pass_count=1,
        state_preservation=(
            "an injected forced decommit failure preserves the free and purge retry bits",
            "the external arena mapping remains owned through retry and only context teardown may unmap it",
        ),
    ),
)

FAULT_POINT_COVERAGE = ("Map", "Commit", "Unmap", "Decommit")

EXCLUSIONS = (
    "No public mi_*, malloc-family, crabc-libc, dynamic-linker, or crabc-rs x86-64 runtime support is exercised or claimed.",
    "No general fault-injection matrix, randomized failure schedule, syscall interposition, or whole-allocator failure-path coverage is exercised or claimed.",
    "No invalid-program or misuse parity is claimed, including double free, use after free, corruption, foreign-pointer, or allocation-API contract behavior.",
    "No complete process/thread lifecycle, pthread callback, cross-thread client routing, abandonment/adoption, or whole-allocator stress regime is exercised or claimed.",
    "No C-oracle differential, sanitizer, Miri, fork, interposition, performance, or public API-surface conclusion follows from these Rust regressions.",
)


def relative(path: Path) -> str:
    """Return a durable repository-relative path when possible."""

    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    """Hash one immutable checked-in evidence input."""

    if not path.is_file():
        raise EvidenceError(f"required evidence input is missing: {relative(path)}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_tool(name: str) -> str:
    """Resolve a tool supplied by the pinned development image."""

    path = shutil.which(name)
    if path is None:
        raise EvidenceError(f"required pinned-image tool is unavailable: {name}")
    return path


def run(command: Sequence[str], *, env: Mapping[str, str] | None = None) -> str:
    """Run one fixed test command and retain its complete diagnostic output."""

    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=dict(env) if env is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    combined = f"{completed.stdout}{completed.stderr}"
    if completed.returncode != 0:
        raise EvidenceError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{combined.strip()}"
        )
    return combined


def require_native_x86_64() -> dict[str, str]:
    """Require host attestation plus a matching Linux/x86-64 guest."""

    execution_mode = os.environ.get("CRABC_EXECUTION_MODE")
    host_architecture = os.environ.get("CRABC_HOST_ARCH")
    if execution_mode != "native" or host_architecture not in {"x86_64", "amd64"}:
        raise EvidenceError(
            "x86-64 fault-injection evidence requires canonical native provenance: "
            "CRABC_EXECUTION_MODE=native and CRABC_HOST_ARCH=x86_64 (or amd64)"
        )
    system = platform.system()
    machine = platform.machine().lower()
    if system != "Linux" or machine not in {"x86_64", "amd64"}:
        raise EvidenceError(
            "x86-64 fault-injection evidence requires the native Linux/x86-64 development image; "
            f"observed {system}/{platform.machine()}"
        )
    return {"execution_mode": "native", "host_architecture": host_architecture}


def toolchain_record(cargo: str, rustc: str) -> dict[str, str]:
    """Prove the native compiler host before the fixed target tests run."""

    rustc_version = run([rustc, "-vV"])
    host_match = RUSTC_HOST.search(rustc_version)
    if host_match is None or host_match.group("target") != TARGET:
        observed = host_match.group("target") if host_match is not None else "<missing>"
        raise EvidenceError(
            f"x86-64 fault-injection evidence requires rustc host {TARGET}, observed {observed}"
        )
    cargo_version = run([cargo, "--version"]).strip()
    release = next(
        (line.removeprefix("release: ") for line in rustc_version.splitlines() if line.startswith("release: ")),
        "<missing>",
    )
    return {
        "cargo": cargo_version,
        "rustc_host": TARGET,
        "rustc_release": release,
    }


def cargo_test_command(cargo: str, lane: FaultLane, target_dir: Path) -> list[str]:
    """Build one exact, locked, target-isolated Cargo invocation for ``lane``."""

    return [
        cargo,
        "test",
        "--locked",
        "--target",
        TARGET,
        "--target-dir",
        str(target_dir),
        "-p",
        "crabc-mimalloc",
        "--lib",
        lane.test_filter,
        "--",
        "--test-threads=1",
        "--exact",
    ]


def normalized_command(command: Sequence[str], target_dir: Path) -> list[str]:
    """Keep the durable report deterministic while retaining isolation proof."""

    return [
        "<isolated-temporary-target-dir>" if part == str(target_dir) else part
        for part in command
    ]


def parse_test_result(output: str, lane: FaultLane) -> dict[str, int]:
    """Require exactly one successful lib-test summary for a fixed lane."""

    matches = list(TEST_RESULT.finditer(output))
    if len(matches) != 1:
        raise EvidenceError(
            f"{lane.identifier} produced {len(matches)} lib-test summaries, expected exactly one"
        )
    match = matches[0]
    result = {
        "passed": int(match.group("passed")),
        "failed": int(match.group("failed")),
        "ignored": int(match.group("ignored")),
        "measured": int(match.group("measured")),
        "filtered_out": int(match.group("filtered")),
    }
    if match.group("status") != "ok" or result["failed"] != 0:
        raise EvidenceError(f"{lane.identifier} did not pass: {result}")
    if result["passed"] != lane.expected_pass_count:
        raise EvidenceError(
            f"{lane.identifier} passed {result['passed']} tests, "
            f"expected exactly {lane.expected_pass_count}"
        )
    return result


def run_lane(cargo: str, lane: FaultLane, target_dir: Path) -> dict[str, Any]:
    """Execute and record one source-named failure-path regression."""

    command = cargo_test_command(cargo, lane, target_dir)
    result = parse_test_result(run(command), lane)
    return {
        "id": lane.identifier,
        "cargo_command": normalized_command(command, target_dir),
        "fault_points": list(lane.fault_points),
        "expected_pass_count": lane.expected_pass_count,
        "observed": result,
        "source_tests": [lane.test_filter],
        "state_preservation": list(lane.state_preservation),
    }


def report_from_results(
    *,
    provenance: Mapping[str, str],
    toolchain: Mapping[str, str],
    lockfile_sha256: str,
    lanes: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Construct the stable, explicitly incomplete failure-path record."""

    expected = sum(int(lane["expected_pass_count"]) for lane in lanes)
    observed = sum(int(lane["observed"]["passed"]) for lane in lanes)
    report: dict[str, Any] = {
        "format": 1,
        "kind": "mimalloc-x86_64-bounded-fault-injection-evidence",
        "profile": "linux-x86_64-private-engine-fault-injection-foundation",
        "status": "passed",
        "target": {
            "architecture": "x86_64",
            "endianness": "little",
            "rust_target": TARGET,
            "system": "linux",
        },
        "native_execution_provenance": dict(provenance),
        "toolchain": dict(toolchain),
        "cargo": {
            "lockfile": {"path": relative(LOCKFILE), "sha256": lockfile_sha256},
            "locked": True,
            "target_dir": {
                "isolated": True,
                "retained": False,
                "value": "<isolated-temporary-target-dir>",
            },
        },
        "lanes": [dict(lane) for lane in lanes],
        "summary": {
            "expected_pass_count": expected,
            "observed_pass_count": observed,
            "lane_count": len(lanes),
            "named_fault_points": list(FAULT_POINT_COVERAGE),
        },
        "scope": {
            "boundary": "crate-private crabc-mimalloc selected in-process fault-plan regressions only",
            "public_runtime_support": False,
            "general_fault_or_misuse_parity": False,
            "claim": "bounded fault-injection state-preservation foundation",
        },
        "exclusions": list(EXCLUSIONS),
    }
    validate_report(report)
    return report


def validate_report(report: Mapping[str, Any]) -> None:
    """Reject accidental broadening or a partial selected result."""

    required = {
        "cargo",
        "exclusions",
        "format",
        "kind",
        "lanes",
        "native_execution_provenance",
        "profile",
        "scope",
        "status",
        "summary",
        "target",
        "toolchain",
    }
    if set(report) != required:
        raise EvidenceError(f"fault-injection report schema drifted: {sorted(set(report) ^ required)}")
    if report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("fault-injection report must record a passed format-1 result")
    if report["kind"] != "mimalloc-x86_64-bounded-fault-injection-evidence":
        raise EvidenceError("fault-injection report kind drifted")
    if report["profile"] != "linux-x86_64-private-engine-fault-injection-foundation":
        raise EvidenceError("fault-injection report profile drifted")
    if report["target"] != {
        "architecture": "x86_64",
        "endianness": "little",
        "rust_target": TARGET,
        "system": "linux",
    }:
        raise EvidenceError("fault-injection report target drifted")
    if report["native_execution_provenance"] not in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    ):
        raise EvidenceError("fault-injection report lacks canonical native x86-64 provenance")

    scope = report["scope"]
    if not isinstance(scope, Mapping) or scope.get("public_runtime_support") is not False:
        raise EvidenceError("fault-injection report must preserve the non-public runtime boundary")
    if scope.get("general_fault_or_misuse_parity") is not False:
        raise EvidenceError("fault-injection report must reject a general fault/misuse parity claim")
    if scope.get("claim") != "bounded fault-injection state-preservation foundation":
        raise EvidenceError("fault-injection report claim drifted")
    if tuple(report["exclusions"]) != EXCLUSIONS:
        raise EvidenceError("fault-injection report exclusions drifted")

    cargo = report["cargo"]
    if not isinstance(cargo, Mapping) or cargo.get("locked") is not True:
        raise EvidenceError("fault-injection report must retain Cargo --locked evidence")
    if cargo.get("target_dir") != {
        "isolated": True,
        "retained": False,
        "value": "<isolated-temporary-target-dir>",
    }:
        raise EvidenceError("fault-injection report target-directory isolation drifted")

    lanes = report["lanes"]
    if not isinstance(lanes, list) or len(lanes) != len(TEST_LANES):
        raise EvidenceError("fault-injection report lane count drifted")
    expected_ids = [lane.identifier for lane in TEST_LANES]
    if [lane.get("id") for lane in lanes if isinstance(lane, Mapping)] != expected_ids:
        raise EvidenceError("fault-injection report lane selections drifted")

    expected_total = 0
    observed_total = 0
    for configured, observed in zip(TEST_LANES, lanes, strict=True):
        if not isinstance(observed, Mapping):
            raise EvidenceError(f"{configured.identifier} report is not an object")
        if observed.get("fault_points") != list(configured.fault_points):
            raise EvidenceError(f"{configured.identifier} fault-point selection drifted")
        if observed.get("source_tests") != [configured.test_filter]:
            raise EvidenceError(f"{configured.identifier} source-test selection drifted")
        if observed.get("state_preservation") != list(configured.state_preservation):
            raise EvidenceError(f"{configured.identifier} state-preservation assertion drifted")
        if observed.get("expected_pass_count") != configured.expected_pass_count:
            raise EvidenceError(f"{configured.identifier} expected count drifted")
        command = observed.get("cargo_command")
        if not isinstance(command, list) or "--locked" not in command:
            raise EvidenceError(f"{configured.identifier} is missing Cargo --locked")
        target_index = command.index("--target") + 1 if "--target" in command else -1
        if target_index < 1 or command[target_index] != TARGET:
            raise EvidenceError(f"{configured.identifier} is not locked to {TARGET}")
        target_dir_index = command.index("--target-dir") + 1 if "--target-dir" in command else -1
        if target_dir_index < 1 or command[target_dir_index] != "<isolated-temporary-target-dir>":
            raise EvidenceError(f"{configured.identifier} does not use the isolated target directory")
        if "--exact" not in command or "--test-threads=1" not in command:
            raise EvidenceError(f"{configured.identifier} is not a serialized exact test selection")
        result = observed.get("observed")
        if not isinstance(result, Mapping) or result.get("failed") != 0:
            raise EvidenceError(f"{configured.identifier} does not record a clean test result")
        if result.get("passed") != configured.expected_pass_count:
            raise EvidenceError(f"{configured.identifier} observed count drifted")
        expected_total += configured.expected_pass_count
        observed_total += int(result["passed"])

    summary = report["summary"]
    if summary != {
        "expected_pass_count": expected_total,
        "observed_pass_count": observed_total,
        "lane_count": len(TEST_LANES),
        "named_fault_points": list(FAULT_POINT_COVERAGE),
    }:
        raise EvidenceError("fault-injection report summary drifted")
    if observed_total != expected_total:
        raise EvidenceError("fault-injection report records an incomplete test selection")


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    """Atomically publish one fully validated report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
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


def run_evidence(report_path: Path = REPORT) -> dict[str, Any]:
    """Run each fixed failure path and publish its bounded native report."""

    provenance = require_native_x86_64()
    cargo = require_tool("cargo")
    rustc = require_tool("rustc")
    toolchain = toolchain_record(cargo, rustc)
    before_lockfile = sha256_file(LOCKFILE)

    # The directory belongs to this invocation alone and is removed even if a
    # regression fails.  It lives outside the workspace, preventing the test
    # selection from sharing an architecture-neutral cache with another lane.
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-fault-") as temporary:
        target_dir = Path(temporary) / "target"
        lanes = [run_lane(cargo, lane, target_dir) for lane in TEST_LANES]

    after_lockfile = sha256_file(LOCKFILE)
    if after_lockfile != before_lockfile:
        raise EvidenceError("Cargo.lock changed despite the required --locked commands")
    report = report_from_results(
        provenance=provenance,
        toolchain=toolchain,
        lockfile_sha256=before_lockfile,
        lanes=lanes,
    )
    atomic_write_json(report_path, report)
    return report


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        type=Path,
        default=REPORT,
        help="write the bounded evidence report here (default: %(default)s)",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        report = run_evidence(arguments.report)
    except EvidenceError as error:
        print(f"allocator x86-64 fault-injection foundation: FAIL: {error}", file=sys.stderr)
        return 1
    summary = report["summary"]
    print(
        "allocator x86-64 fault-injection foundation: PASS "
        f"({summary['observed_pass_count']} bounded tests across {summary['lane_count']} lanes; "
        f"report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
