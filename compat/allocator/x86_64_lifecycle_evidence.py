#!/usr/bin/env python3
"""Run a deliberately bounded native Linux/x86-64 lifecycle evidence lane.

This judge exercises only the current crate-private lifecycle and concurrency
protocols that have focused Rust tests.  It is intentionally separate from
``run.py``: that runner owns the AArch64 production-oracle contract, whereas
this file records a native x86-64 laboratory result without implying public
``mi_*``, libc, loader, or crabc-rs support.

The lane is fail-closed on the canonical dispatcher provenance.  An x86-64
Docker guest alone is insufficient because it can be QEMU-emulated; the
dispatcher must attest a native x86-64 host through ``CRABC_EXECUTION_MODE``
and ``CRABC_HOST_ARCH``.  Every Cargo invocation also fixes the musl target,
uses ``--locked``, and writes to one disposable target directory outside the
workspace.
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
REPORT = ROOT / "compat/reports/allocator/x86_64/lifecycle-concurrency.json"
LOCKFILE = ROOT / "Cargo.lock"

TEST_RESULT = re.compile(
    r"test result: (?P<status>ok|FAILED)\. "
    r"(?P<passed>\d+) passed; (?P<failed>\d+) failed; "
    r"(?P<ignored>\d+) ignored; (?P<measured>\d+) measured; "
    r"(?P<filtered>\d+) filtered out;"
)
RUSTC_HOST = re.compile(r"^host: (?P<target>\S+)$", re.MULTILINE)


class EvidenceError(RuntimeError):
    """A failed evidence precondition or bounded test lane."""


@dataclass(frozen=True)
class TestLane:
    """One intentionally narrow current-engine test selection."""

    identifier: str
    kind: str
    test_filter: str
    exact_filter: bool
    features: tuple[str, ...]
    expected_pass_count: int
    source_tests: tuple[str, ...]
    bounded_behavior: tuple[str, ...]


# These selections are named rather than discovered.  Adding a new test to a
# module cannot silently enlarge a lifecycle claim: a reviewer must add a
# source-specific behavior statement and expected pass count here first.
TEST_LANES = (
    TestLane(
        identifier="compiler-tls-fresh-native-thread",
        kind="native-unit",
        test_filter="compiler_tls::tests::fresh_native_thread_starts_with_the_source_root_images",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "compiler_tls::tests::fresh_native_thread_starts_with_the_source_root_images",
        ),
        bounded_behavior=(
            "one spawned native thread starts with the immutable compiler-TLS root images",
            "the direct thread-pointer identity and source-helper TLS address remain aligned",
        ),
    ),
    TestLane(
        identifier="compiler-tls-explicit-reset",
        kind="native-unit",
        test_filter="compiler_tls::tests::native_thread_roots_install_and_reset_without_a_stale_fallback",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "compiler_tls::tests::native_thread_roots_install_and_reset_without_a_stale_fallback",
        ),
        bounded_behavior=(
            "one spawned native thread can install each private root and explicitly reset it",
            "post-reset regular access stays empty instead of reviving a stale fallback",
        ),
    ),
    TestLane(
        identifier="compiler-tls-overlapping-native-threads",
        kind="native-unit",
        test_filter="compiler_tls::tests::compiler_tls_roots_are_isolated_while_native_threads_overlap",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "compiler_tls::tests::compiler_tls_roots_are_isolated_while_native_threads_overlap",
        ),
        bounded_behavior=(
            "two overlapping native threads retain distinct direct thread-pointer identities and TLS addresses",
            "resetting one thread's roots does not overwrite the other thread's installed roots",
        ),
    ),
    TestLane(
        identifier="owned-tls-key-registry-concurrent-claim-release",
        kind="native-unit",
        test_filter="owned_tls_key_registry::tests::concurrent_claims_are_unique_and_explicit_releases_restore_lowest_order",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "owned_tls_key_registry::tests::concurrent_claims_are_unique_and_explicit_releases_restore_lowest_order",
        ),
        bounded_behavior=(
            "four scoped workers each claim 32 distinct private registry keys",
            "explicit releases restore the lowest source-order key before registry shutdown",
        ),
    ),
    TestLane(
        identifier="remote-free-joined-multi-producer",
        kind="native-unit",
        test_filter="remote_free::tests::std_multi_producer_pushes_are_all_collected_once",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "remote_free::tests::std_multi_producer_pushes_are_all_collected_once",
        ),
        bounded_behavior=(
            "eight scoped producers publish 64 blocks each to one live owner-associated test page",
            "the sole owner joins producers and collects all 512 blocks exactly once",
        ),
    ),
    TestLane(
        identifier="remote-free-owner-collection-race",
        kind="native-unit",
        test_filter="remote_free::tests::owner_collection_races_a_producer_without_losing_or_double_collecting_blocks",
        exact_filter=True,
        features=(),
        expected_pass_count=1,
        source_tests=(
            "remote_free::tests::owner_collection_races_a_producer_without_losing_or_double_collecting_blocks",
        ),
        bounded_behavior=(
            "a sole owner repeatedly collects while one scoped producer publishes 128 blocks",
            "the bounded live owner-associated protocol neither loses nor double-collects those blocks",
        ),
    ),
    TestLane(
        identifier="remote-free-finite-loom-head-protocols",
        kind="finite-loom",
        test_filter="remote_free::loom_tests",
        exact_filter=False,
        features=("loom",),
        expected_pass_count=5,
        source_tests=(
            "remote_free::loom_tests::loom_multiple_remote_publishers_preserve_owner_bit_and_collect_every_block_once",
            "remote_free::loom_tests::loom_owner_collection_racing_publication_loses_no_block_and_keeps_owner_bit",
            "remote_free::loom_tests::loom_bitmap_adopter_racing_abandoned_publisher_has_one_owner_and_correct_bitmap_responsibility",
            "remote_free::loom_tests::loom_abandoned_unown_racing_publisher_either_transfers_or_retains_collection_obligation",
            "remote_free::loom_tests::loom_expected_head_unown_racing_allow_collect_publisher_preserves_the_head_or_collection",
        ),
        bounded_behavior=(
            "Loom explores the modeled two-producer live-head publication and collection interleavings",
            "Loom explores the modeled abandoned-head claim and unown transitions with one owner bit",
            "the model covers only integer head/link identities and the production atomic transition helpers",
        ),
    ),
)

EXCLUSIONS = (
    "No public mi_*, malloc-family, crabc-libc, dynamic-linker, or crabc-rs x86-64 runtime support is exercised or claimed.",
    "No complete process or pthread/TLS callback lifecycle is exercised or claimed.",
    "No general allocation/free routing, cross-thread client API, owner-exit traversal, adoption, or whole-allocator stress regime is exercised or claimed.",
    "The Loom lane does not model page identity, arena lookup, bitmap fields, retirement/release, compiler TLS, or owner-local used/local_free mutation.",
    "No C-oracle differential, fault injection, fork, interposition, sanitizer, performance, or API-surface conclusion follows from these Rust tests.",
)


def relative(path: Path) -> str:
    """Return a durable repository-relative path when possible."""

    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    if not path.is_file():
        raise EvidenceError(f"required evidence input is missing: {relative(path)}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise EvidenceError(f"required pinned-image tool is unavailable: {name}")
    return path


def run(command: Sequence[str], *, env: Mapping[str, str] | None = None) -> str:
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
    """Require host attestation and the matching Linux/x86-64 guest."""

    execution_mode = os.environ.get("CRABC_EXECUTION_MODE")
    host_architecture = os.environ.get("CRABC_HOST_ARCH")
    if execution_mode != "native" or host_architecture not in {"x86_64", "amd64"}:
        raise EvidenceError(
            "x86-64 lifecycle evidence requires canonical native provenance: "
            "CRABC_EXECUTION_MODE=native and CRABC_HOST_ARCH=x86_64 (or amd64)"
        )
    system = platform.system()
    machine = platform.machine().lower()
    if system != "Linux" or machine not in {"x86_64", "amd64"}:
        raise EvidenceError(
            "x86-64 lifecycle evidence requires the native Linux/x86-64 development image; "
            f"observed {system}/{platform.machine()}"
        )
    return {"execution_mode": "native", "host_architecture": host_architecture}


def toolchain_record(cargo: str, rustc: str) -> dict[str, str]:
    """Prove the native compiler host before running the fixed target tests."""

    rustc_version = run([rustc, "-vV"])
    host_match = RUSTC_HOST.search(rustc_version)
    if host_match is None or host_match.group("target") != TARGET:
        observed = host_match.group("target") if host_match is not None else "<missing>"
        raise EvidenceError(
            f"x86-64 lifecycle evidence requires rustc host {TARGET}, observed {observed}"
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


def cargo_test_command(cargo: str, lane: TestLane, target_dir: Path) -> list[str]:
    """Build one locked, exact target-specific test command for ``lane``."""

    command = [
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
    ]
    if lane.features:
        command.extend(("--features", ",".join(lane.features)))
    command.append(lane.test_filter)
    command.extend(("--", "--test-threads=1"))
    if lane.exact_filter:
        command.append("--exact")
    return command


def normalized_command(command: Sequence[str], target_dir: Path) -> list[str]:
    """Keep the durable report deterministic while retaining target isolation."""

    return [
        "<isolated-temporary-target-dir>" if part == str(target_dir) else part
        for part in command
    ]


def parse_test_result(output: str, lane: TestLane) -> dict[str, int]:
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


def run_lane(cargo: str, lane: TestLane, target_dir: Path) -> dict[str, Any]:
    command = cargo_test_command(cargo, lane, target_dir)
    result = parse_test_result(run(command), lane)
    return {
        "id": lane.identifier,
        "kind": lane.kind,
        "cargo_command": normalized_command(command, target_dir),
        "expected_pass_count": lane.expected_pass_count,
        "observed": result,
        "source_tests": list(lane.source_tests),
        "bounded_behavior": list(lane.bounded_behavior),
    }


def report_from_results(
    *,
    provenance: Mapping[str, str],
    toolchain: Mapping[str, str],
    lockfile_sha256: str,
    lanes: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Construct the stable, deliberately incomplete evidence record."""

    expected = sum(int(lane["expected_pass_count"]) for lane in lanes)
    observed = sum(int(lane["observed"]["passed"]) for lane in lanes)
    report: dict[str, Any] = {
        "format": 1,
        "kind": "mimalloc-x86_64-bounded-lifecycle-concurrency-evidence",
        "profile": "linux-x86_64-private-engine-lifecycle-concurrency-foundation",
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
        },
        "scope": {
            "boundary": "crate-private crabc-mimalloc engine unit and finite Loom evidence only",
            "public_runtime_support": False,
            "claim": "bounded lifecycle and concurrency foundation",
        },
        "exclusions": list(EXCLUSIONS),
    }
    validate_report(report)
    return report


def validate_report(report: Mapping[str, Any]) -> None:
    """Reject accidental broadening or a partial test result before publication."""

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
        raise EvidenceError(f"lifecycle report schema drifted: {sorted(set(report) ^ required)}")
    if report["format"] != 1 or report["status"] != "passed":
        raise EvidenceError("lifecycle report must record a passed format-1 result")
    if report["kind"] != "mimalloc-x86_64-bounded-lifecycle-concurrency-evidence":
        raise EvidenceError("lifecycle report kind drifted")
    if report["profile"] != "linux-x86_64-private-engine-lifecycle-concurrency-foundation":
        raise EvidenceError("lifecycle report profile drifted")
    if report["target"] != {
        "architecture": "x86_64",
        "endianness": "little",
        "rust_target": TARGET,
        "system": "linux",
    }:
        raise EvidenceError("lifecycle report target drifted")
    if report["native_execution_provenance"] not in (
        {"execution_mode": "native", "host_architecture": "x86_64"},
        {"execution_mode": "native", "host_architecture": "amd64"},
    ):
        raise EvidenceError("lifecycle report lacks canonical native x86-64 provenance")
    scope = report["scope"]
    if not isinstance(scope, Mapping) or scope.get("public_runtime_support") is not False:
        raise EvidenceError("lifecycle report must preserve the non-public runtime boundary")
    if scope.get("claim") != "bounded lifecycle and concurrency foundation":
        raise EvidenceError("lifecycle report claim drifted")
    if tuple(report["exclusions"]) != EXCLUSIONS:
        raise EvidenceError("lifecycle report exclusions drifted")

    cargo = report["cargo"]
    if not isinstance(cargo, Mapping) or cargo.get("locked") is not True:
        raise EvidenceError("lifecycle report must retain Cargo --locked evidence")
    target_dir = cargo.get("target_dir")
    if target_dir != {
        "isolated": True,
        "retained": False,
        "value": "<isolated-temporary-target-dir>",
    }:
        raise EvidenceError("lifecycle report target-directory isolation drifted")

    lanes = report["lanes"]
    if not isinstance(lanes, list) or len(lanes) != len(TEST_LANES):
        raise EvidenceError("lifecycle report lane count drifted")
    expected_ids = [lane.identifier for lane in TEST_LANES]
    if [lane.get("id") for lane in lanes if isinstance(lane, Mapping)] != expected_ids:
        raise EvidenceError("lifecycle report lane selections drifted")

    expected_total = 0
    observed_total = 0
    for configured, observed in zip(TEST_LANES, lanes, strict=True):
        if not isinstance(observed, Mapping):
            raise EvidenceError(f"{configured.identifier} report is not an object")
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
    }:
        raise EvidenceError("lifecycle report summary drifted")
    if observed_total != expected_total:
        raise EvidenceError("lifecycle report records an incomplete test selection")


def atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
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
    """Execute every fixed current-engine selection and publish one report."""

    provenance = require_native_x86_64()
    cargo = require_tool("cargo")
    rustc = require_tool("rustc")
    toolchain = toolchain_record(cargo, rustc)
    before_lockfile = sha256_file(LOCKFILE)

    # The target directory belongs to this invocation alone and is removed
    # even if a selected test fails.  It deliberately lives outside the
    # workspace so it cannot leak an architecture-neutral build cache into
    # another evidence lane.
    with tempfile.TemporaryDirectory(prefix="crabc-mimalloc-x86_64-lifecycle-") as temporary:
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
        print(f"allocator x86-64 lifecycle/concurrency foundation: FAIL: {error}", file=sys.stderr)
        return 1
    summary = report["summary"]
    print(
        "allocator x86-64 lifecycle/concurrency foundation: PASS "
        f"({summary['observed_pass_count']} bounded tests across {summary['lane_count']} lanes; "
        f"report: {relative(arguments.report)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
