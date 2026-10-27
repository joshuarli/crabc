#!/usr/bin/env python3
"""Fail-closed native Linux/x86-64 gate for persistent allocator lifecycle.

The full profile requires persistent concurrency and lifecycle evidence,
structural audits, and early engine throughput. The correctness profile
requires the same functional evidence and production architecture checks while
deferring codegen optimization and throughput qualification. Its receipt cannot
qualify performance.

Evidence is one of four shapes:

* `native_tests`: `crabc-mimalloc/tests/native_*` integration targets, each
  built and run independently with its default-off audit and fault features.
  Every such target belongs to exactly one native evidence entry, so a new direct
  runtime witness cannot silently escape the evidence closure.
* `command`: an allocator-container command (`python3 <script> ...`). The
  one `{scratch}` placeholder names this run's fresh per-evidence directory.
* `receipt`: a runtime-launcher runner's revision-bound receipt, read and
  validated through the shared `compat/x86_64/native_shadow_receipt.py`
  reader: it must seal this exact checkout, record a canonical run, cite
  digest-matching raw logs, and contain at least one passing case of the
  named family with every case passing.
* `command: null`: evidence that exists only outside this launcher. It is
  declared missing here, so a gate that depends on it must name a blocker.

A gate passes only when it carries no reviewed blocker and every evidence
entry executed successfully on this run. Runnable evidence is always
executed; its pass never removes a blocker by itself.
"""

from __future__ import annotations

import argparse
import ctypes
from contextlib import contextmanager, nullcontext
import math
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence, TextIO

import run as harness
import perf_engine_x86_64 as engine
import perf_integrated_x86_64 as integrated

sys.path.insert(0, str(harness.ROOT / "compat/x86_64"))
import native_shadow_receipt  # noqa: E402


CONTRACT = harness.ALLOCATOR_ROOT / "m5-gate-x86_64-v3.5.0.json"
SCHEMA = "crabc-mimalloc-x86_64-m5-gate"
GATE_IDS = (
    "m5.pointer-dispatch",
    "m5.remote-publication",
    "m5.generic-exit",
    "m5.abandon-reclaim-release",
    "m5.no-forbidden-scaffolding",
    "m5.libc-shadow",
    "m5.state-auditing",
    "m5.churn-soak",
    "m5.upstream-stress",
    "m5.codegen-performance",
)
NATIVE_TESTS = harness.ROOT / "crabc-mimalloc/tests"
NATIVE_TEST_PREFIX = "native_"
NATIVE_FEATURES = "native-runtime-test-audit,native-runtime-test-fault"
# These two test targets compile their behavior only when the owning allocator
# mode is enabled. Public growth has separate secure and guarded profiles.
NATIVE_TEST_EXTRA_FEATURE_PROFILES = {
    "native_secure_public_growth": (("mi-secure-3",), ("mi-guarded",)),
    "native_secure_os_release_lifecycle": (("mi-secure-5",),),
}
RUST_TARGET = "x86_64-unknown-linux-musl"
EVIDENCE_TIMEOUT_SECONDS = 3600
SCRATCH_PLACEHOLDER = "{scratch}"
INTERNAL_NATIVE_TEST_MODE = "--internal-native-tests"
RUST_TEST_SUMMARY = re.compile(
    r"^test result: (?P<status>ok|FAILED)\. (?P<passed>[0-9]+) passed; "
    r"(?P<failed>[0-9]+) failed; (?P<ignored>[0-9]+) ignored; "
    r"(?P<measured>[0-9]+) measured; (?P<filtered>[0-9]+) filtered out;",
    flags=re.MULTILINE,
)
NATIVE_PROCESS_TERMINATION_GRACE_SECONDS = 5
PR_SET_CHILD_SUBREAPER = 36
ARTIFACTS = harness.ARTIFACT_ROOT / "x86_64/m5-gate"
QUALIFICATION_PROFILES = ("full", "correctness")
CORRECTNESS_DEFERRED_GATE = "m5.codegen-performance"
CORRECTNESS_DEFERRED_EVIDENCE = ["codegen:hot-path-audit", "perf:engine-early-proof"]
EARLY_ENGINE_PROOF_EVIDENCE = "perf:engine-early-proof"
EARLY_ENGINE_MINIMUM_LOWER_95 = 0.25
INTERNAL_ENGINE_PROOF_MODE = "--internal-engine-proof"


class NativeProcessCancelled(Exception):
    """The M5 evidence owner received a termination signal."""

    def __init__(self, signum: int) -> None:
        super().__init__(f"received signal {signum}")
        self.signum = signum


class NativeCancellation:
    """Record cancellation until a newly spawned process has an explicit owner."""

    def __init__(self, previous: Mapping[int, Any]) -> None:
        self.previous = dict(previous)
        self._deferred = 0
        self._pending_signum: int | None = None

    def handle(self, signum: int, _frame: Any) -> None:
        if self._deferred:
            if self._pending_signum is None:
                self._pending_signum = signum
            return
        raise NativeProcessCancelled(signum)

    @contextmanager
    def defer_until_owned(self) -> Iterator[None]:
        """Queue signals across Popen and handle publication without masking the child."""

        self._deferred += 1
        try:
            yield
        except BaseException as error:
            self._deferred -= 1
            if self._deferred == 0 and self._pending_signum is not None:
                signum = self._pending_signum
                self._pending_signum = None
                raise NativeProcessCancelled(signum) from error
            raise
        else:
            self._deferred -= 1
            if self._deferred == 0 and self._pending_signum is not None:
                signum = self._pending_signum
                self._pending_signum = None
                raise NativeProcessCancelled(signum)


def _install_cancellation_handlers() -> NativeCancellation:
    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    cancellation = NativeCancellation(previous)
    for signum in previous:
        signal.signal(signum, cancellation.handle)
    return cancellation


def _restore_signal_handlers(previous: Mapping[int, Any]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _ignore_cancellation_signals() -> dict[int, Any]:
    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    for signum in previous:
        signal.signal(signum, signal.SIG_IGN)
    return previous


def _enable_child_subreaper() -> None:
    """Adopt orphaned Cargo descendants so this helper can reap them after group teardown."""

    if not sys.platform.startswith("linux"):
        raise harness.HarnessError("M5 native process ownership requires Linux child subreaping")
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    ctypes.set_errno(0)
    if prctl(
        PR_SET_CHILD_SUBREAPER,
        ctypes.c_ulong(1),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    ) != 0:
        error = ctypes.get_errno()
        raise harness.HarnessError(f"cannot own native Cargo descendants: {os.strerror(error)}")


class NativeProcessHelper:
    """Own each Cargo process group, including descendants after timeout or cancellation."""

    def __init__(self, cancellation: NativeCancellation | None = None) -> None:
        self._active: subprocess.Popen[str] | None = None
        self._cancellation = cancellation

    @staticmethod
    def _signal_group(pgid: int, signum: int) -> None:
        try:
            os.killpg(pgid, signum)
        except ProcessLookupError:
            pass

    @staticmethod
    def _group_exists(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False
        return True

    @staticmethod
    def _reap_group_children(pgid: int) -> None:
        while True:
            try:
                os.waitpid(-pgid, 0)
            except InterruptedError:
                continue
            except ChildProcessError:
                return

    @staticmethod
    def _reap_exited_group_children(pgid: int) -> None:
        while True:
            try:
                pid, _status = os.waitpid(-pgid, os.WNOHANG)
                if pid == 0:
                    return
            except InterruptedError:
                continue
            except ChildProcessError:
                return

    def _stop_active(self) -> tuple[str, str]:
        process = self._active
        if process is None:
            return "", ""
        previous = _ignore_cancellation_signals()
        try:
            self._signal_group(process.pid, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(
                    timeout=NATIVE_PROCESS_TERMINATION_GRACE_SECONDS,
                )
            except subprocess.TimeoutExpired:
                self._signal_group(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
            self._signal_group(process.pid, signal.SIGKILL)
            self._reap_group_children(process.pid)
            return stdout or "", stderr or ""
        finally:
            self._active = None
            _restore_signal_handlers(previous)

    def run(self, command: Sequence[str], *, timeout_seconds: int | None) -> dict[str, Any]:
        if timeout_seconds is not None and (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
        ):
            raise harness.HarnessError("native target timeout must be a positive number of seconds")
        process: subprocess.Popen[str] | None = None
        try:
            cancellation_scope = (
                self._cancellation.defer_until_owned()
                if self._cancellation is not None else nullcontext()
            )
            try:
                with cancellation_scope:
                    process = subprocess.Popen(
                        list(command), cwd=harness.ROOT, text=True, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, start_new_session=True,
                    )
                    self._active = process
            except OSError as error:
                return {
                    "command": list(command), "status": 127, "stdout": "", "stderr": str(error),
                }
            try:
                stdout, stderr = process.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                stdout, stderr = self._stop_active()
                return {
                    "command": list(command), "status": 124, "stdout": stdout, "stderr": stderr,
                    "timed_out": True,
                }
            if process.returncode is None:
                raise harness.HarnessError("native Cargo process returned without an exit status")
            self._reap_exited_group_children(process.pid)
            if self._group_exists(process.pid):
                self._stop_active()
                return {
                    "command": list(command), "status": 1, "stdout": stdout or "",
                    "stderr": (stderr or "") + "native command left child processes running\n",
                }
            return {
                "command": list(command), "status": process.returncode,
                "stdout": stdout or "", "stderr": stderr or "",
            }
        except BaseException:
            try:
                self._stop_active()
            except BaseException as cleanup_error:
                print(f"M5 native process cleanup failed: {cleanup_error}", file=sys.stderr, flush=True)
            raise
        finally:
            if process is not None and self._active is process and process.returncode is not None:
                self._active = None


def run_native_helper_process(command: Sequence[str], log: Path) -> int:
    """Run the native-target helper without a cumulative timeout and retain output live."""

    cancellation = _install_cancellation_handlers()
    process: subprocess.Popen[bytes] | None = None
    try:
        with log.open("wb") as output:
            with cancellation.defer_until_owned():
                process = subprocess.Popen(
                    list(command), cwd=harness.ROOT, stdout=output, stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            return process.wait()
    except BaseException:
        if process is not None and process.poll() is None:
            cleanup_handlers = _ignore_cancellation_signals()
            try:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                process.wait()
            finally:
                _restore_signal_handlers(cleanup_handlers)
        raise
    finally:
        _restore_signal_handlers(cancellation.previous)


def _string_list(value: object, subject: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or not all(isinstance(entry, str) and entry for entry in value)
        or len(set(value)) != len(value)
    ):
        raise harness.HarnessError(f"M5 gate {subject} must be a list of unique non-empty strings")
    return list(value)


def native_test_targets(tests_root: Path = NATIVE_TESTS) -> set[str]:
    """Every direct native runtime integration target in the crate."""

    return {path.stem for path in tests_root.glob(f"{NATIVE_TEST_PREFIX}*.rs")}


def native_test_group_command(targets: Sequence[str]) -> list[str]:
    """Run the gate's internal per-target executor for one checked roster."""

    return [
        "python3", harness.relative(Path(__file__)), INTERNAL_NATIVE_TEST_MODE, *targets,
    ]


def engine_early_proof_command() -> list[str]:
    """Read the canonical qualified engine report through this gate's CLI."""

    return ["python3", harness.relative(Path(__file__)), INTERNAL_ENGINE_PROOF_MODE]


def native_test_feature_profiles(target: str) -> tuple[tuple[str, ...], ...]:
    """Return every required audit-feature profile for one native target."""

    base = tuple(NATIVE_FEATURES.split(","))
    extras = NATIVE_TEST_EXTRA_FEATURE_PROFILES.get(target, ((),))
    return tuple((*base, *profile) for profile in extras)


def native_test_command(target: str, features: Sequence[str]) -> list[str]:
    """Run exactly one native integration target with one feature profile."""

    command = [
        "cargo", "test", "--locked", "--target", RUST_TARGET, "-p", "crabc-mimalloc",
        "--no-default-features", "--features", ",".join(features), "--no-fail-fast",
        "--test", target,
    ]
    return command


def native_test_group_targets(runnable_evidence: Mapping[str, Any]) -> list[list[str]]:
    """Return the checked target rosters carried by internal helper commands."""

    prefix = native_test_group_command([])
    return [
        list(command[len(prefix):])
        for command in runnable_evidence.values()
        if isinstance(command, list) and command[:len(prefix)] == prefix
    ]


def is_native_test_group_command(command: Any) -> bool:
    prefix = native_test_group_command([])
    return isinstance(command, list) and command[:len(prefix)] == prefix and len(command) > len(prefix)


def native_test_roster_issue(targets: Sequence[str], expected_rosters: Sequence[Sequence[str]]) -> str | None:
    """Require an internal helper invocation to name one exact evidence roster."""

    if not isinstance(targets, Sequence) or isinstance(targets, (str, bytes)):
        return "native target roster is invalid"
    if not targets:
        return "native target roster is empty"
    if any(not isinstance(target, str) or not target for target in targets):
        return "native target roster contains an invalid target"
    if len(set(targets)) != len(targets):
        return "native target roster contains a duplicate target"
    target_set = set(targets)
    expected = [list(roster) for roster in expected_rosters]
    if list(targets) not in expected:
        if any(target_set < set(roster) for roster in expected):
            return "native target roster is missing checked targets"
        if any(set(roster) < target_set for roster in expected):
            return "native target roster includes extra targets"
        return "native target roster does not match a checked evidence group"
    return None


def native_test_run_issue(target: str, record: Mapping[str, Any]) -> str | None:
    """Require a passing parent libtest summary after all child output."""

    status = record.get("status")
    if not isinstance(status, int) or isinstance(status, bool):
        return f"native target {target} Cargo command returned an invalid status"
    if record.get("timed_out") is True:
        return f"native target {target} exceeded its {EVIDENCE_TIMEOUT_SECONDS}-second runtime limit"
    output = record.get("stdout")
    if not isinstance(output, str):
        return f"native target {target} produced no parent test summary"
    summaries = list(RUST_TEST_SUMMARY.finditer(output))
    if not summaries:
        if status != 0:
            return f"native target {target} Cargo command exited with status {status}"
        return f"native target {target} produced no parent test summary"
    parent = summaries[-1]
    passed = int(parent.group("passed"))
    failed = int(parent.group("failed"))
    if parent.group("status") != "ok" or failed != 0:
        return f"native target {target} did not finish with a passing parent summary"
    if passed == 0:
        return f"native target {target} ran no successful tests"
    if status != 0:
        return f"native target {target} Cargo command exited with status {status}"
    return None


def _write_native_log(output: TextIO | None, records: list[str], text: str) -> None:
    if output is None:
        records.append(text)
    else:
        output.write(text)
        output.flush()


def _format_native_command_record(label: str, record: Mapping[str, Any]) -> str:
    return "\n".join((
        f"--- {label} ---",
        f"exit status: {record.get('status')}",
        "stdout:",
        str(record.get("stdout", "")),
        "stderr:",
        str(record.get("stderr", "")),
        "",
    ))


def execute_native_test_group(
    targets: Sequence[str], *, output: TextIO | None = None,
    process_helper: NativeProcessHelper | None = None,
) -> tuple[int, str]:
    """Run each checked target/profile and flush its completed output to the gate log."""

    overall_status = 0
    records: list[str] = []
    owner = NativeProcessHelper() if process_helper is None else process_helper
    for target in targets:
        for features in native_test_feature_profiles(target):
            command = native_test_command(target, features)
            build_command = harness.cargo_test_build_command(command)
            prelude = [
                f"=== native target {target} ({','.join(features)}) ===",
                f"test command: {shlex.join(command)}",
            ]
            if build_command is not None:
                prelude.append(f"build command: {shlex.join(build_command)}")
            _write_native_log(output, records, "\n".join(prelude) + "\n")

            build_record = None
            issue = None
            if build_command is not None:
                build_record = owner.run(build_command, timeout_seconds=None)
                _write_native_log(
                    output, records, _format_native_command_record("build", build_record),
                )
                if build_record["status"] != 0:
                    issue = f"native target {target} Cargo build exited with status {build_record['status']}"
            if issue is None:
                record = owner.run(command, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
                issue = native_test_run_issue(target, record)
                _write_native_log(output, records, _format_native_command_record("test", record))
            if issue is not None:
                overall_status = 1
            _write_native_log(
                output, records,
                f"--- validation ---\n{f'failed: {issue}' if issue is not None else 'passed'}\n\n",
            )
    return overall_status, "" if output is not None else "".join(records)


def run_native_test_helper(targets: Sequence[str], output: TextIO) -> int:
    """Own cancellation and descendant cleanup while running one checked roster."""

    _enable_child_subreaper()
    cancellation = _install_cancellation_handlers()
    owner = NativeProcessHelper(cancellation)
    try:
        status, _ = execute_native_test_group(targets, output=output, process_helper=owner)
        return status
    except NativeProcessCancelled as error:
        print(f"M5 native target evidence interrupted: {error}", file=sys.stderr, flush=True)
        return 128 + error.signum
    finally:
        try:
            owner._stop_active()
        finally:
            _restore_signal_handlers(cancellation.previous)


def validate_contract(
    contract: Mapping[str, Any], pin: Mapping[str, str], native_targets: set[str]
) -> dict[str, Any]:
    """Validate gate identity, evidence honesty, and native-target closure."""

    if contract.get("schema") != SCHEMA or contract.get("format") != 1:
        raise harness.HarnessError("unsupported M5 allocator gate contract")
    if contract.get("qualification_profiles") != {
        "full": {"deferred_evidence": []},
        "correctness": {"deferred_evidence": CORRECTNESS_DEFERRED_EVIDENCE},
    }:
        raise harness.HarnessError("M5 qualification profiles must defer only codegen optimization and early throughput evidence")
    upstream = contract.get("upstream")
    if not isinstance(upstream, Mapping) or dict(upstream) != {
        "version": pin["version"], "revision": pin["revision"],
    }:
        raise harness.HarnessError("M5 allocator gate upstream identity mismatch")

    evidence = contract.get("evidence")
    if not isinstance(evidence, Mapping) or not evidence:
        raise harness.HarnessError("M5 allocator gate lacks an evidence registry")
    runnable: dict[str, list[str] | dict[str, str]] = {}
    claimed: dict[str, str] = {}
    for evidence_id, record in evidence.items():
        if not isinstance(record, Mapping) or not isinstance(record.get("scope"), str) or not record["scope"]:
            raise harness.HarnessError(f"M5 evidence {evidence_id} lacks a scope")
        shape = set(record) - {"scope"}
        if shape == {"native_tests"}:
            targets = _string_list(record["native_tests"], f"evidence {evidence_id} native tests")
            for target in targets:
                if target not in native_targets:
                    raise harness.HarnessError(f"M5 evidence {evidence_id} names an absent native target: {target}")
                if target in claimed:
                    raise harness.HarnessError(
                        f"M5 native target {target} is claimed by both {claimed[target]} and {evidence_id}"
                    )
                claimed[target] = evidence_id
            runnable[evidence_id] = native_test_group_command(targets)
        elif shape == {"command"}:
            command = record["command"]
            if evidence_id == EARLY_ENGINE_PROOF_EVIDENCE and command != engine_early_proof_command():
                raise harness.HarnessError(
                    "M5 early engine proof must execute the canonical qualified-report reader"
                )
            if command is None:
                continue
            command = _string_list(command, f"evidence {evidence_id} command")
            if len(command) < 2 or command[0] != "python3" or not (harness.ROOT / command[1]).is_file():
                raise harness.HarnessError(f"M5 evidence {evidence_id} names an absent runner")
            if sum(argument.count(SCRATCH_PLACEHOLDER) for argument in command) > 1:
                raise harness.HarnessError(f"M5 evidence {evidence_id} names more than one scratch directory")
            runnable[evidence_id] = command
        elif shape == {"receipt"}:
            check = record["receipt"]
            if (
                not isinstance(check, Mapping)
                or set(check) != {"runner", "case_prefix"}
                or not isinstance(check["runner"], str)
                or not native_shadow_receipt.RUNNER_RE.match(check["runner"])
                or not isinstance(check["case_prefix"], str)
                or not check["case_prefix"]
            ):
                raise harness.HarnessError(f"M5 evidence {evidence_id} names a malformed receipt check")
            runnable[evidence_id] = dict(check)
        else:
            raise harness.HarnessError(
                f"M5 evidence {evidence_id} must record scope with exactly native_tests, command, or receipt"
            )
    # A native target may instead belong to another gate, which
    # must name that contract; it is then neither run nor claimed here.
    elsewhere = contract.get("native_tests_owned_elsewhere", {})
    if not isinstance(elsewhere, Mapping):
        raise harness.HarnessError("M5 native_tests_owned_elsewhere must map targets to their owning gate")
    for target, owner in elsewhere.items():
        if target not in native_targets:
            raise harness.HarnessError(f"M5 names an absent native target as owned elsewhere: {target}")
        if target in claimed:
            raise harness.HarnessError(f"M5 native target {target} is both claimed and owned elsewhere")
        if not isinstance(owner, str) or not (harness.ROOT / owner).is_file() or target not in (
            harness.ROOT / owner
        ).read_text():
            raise harness.HarnessError(f"M5 native target {target} names an owning gate that does not cite it")
    unclaimed = sorted(native_targets - set(claimed) - set(elsewhere))
    if unclaimed:
        raise harness.HarnessError(f"M5 evidence omits native integration targets: {unclaimed}")

    gates = contract.get("gates")
    if not isinstance(gates, list) or [
        gate.get("id") if isinstance(gate, Mapping) else None for gate in gates
    ] != list(GATE_IDS):
        raise harness.HarnessError("M5 allocator gate order or identity changed")
    referenced: set[str] = set()
    blocked: list[str] = []
    for gate in gates:
        gate_id = gate["id"]
        if set(gate) != {"id", "required", "acceptance", "evidence", "blocked_by"}:
            raise harness.HarnessError(f"M5 gate {gate_id} has unexpected fields")
        if gate["required"] is not True:
            raise harness.HarnessError(f"M5 gate {gate_id} must remain required")
        if not isinstance(gate["acceptance"], str) or not gate["acceptance"]:
            raise harness.HarnessError(f"M5 gate {gate_id} lacks an acceptance contract")
        gate_evidence = _string_list(gate["evidence"], f"{gate_id} evidence")
        unknown = [entry for entry in gate_evidence if entry not in evidence]
        if unknown:
            raise harness.HarnessError(f"M5 gate {gate_id} names undeclared evidence: {unknown}")
        referenced.update(gate_evidence)
        blockers = _string_list(gate["blocked_by"], f"{gate_id} blockers", allow_empty=True)
        if any(entry not in runnable for entry in gate_evidence) and not blockers:
            raise harness.HarnessError(f"M5 gate {gate_id} depends on missing evidence without a blocker")
        if blockers:
            blocked.append(gate_id)
    unreferenced = sorted(set(evidence) - referenced)
    if unreferenced:
        raise harness.HarnessError(f"M5 evidence is declared but unused: {unreferenced}")
    return {
        "blocked_gate_ids": blocked,
        "gate_ids": list(GATE_IDS),
        "missing_evidence": sorted(set(evidence) - set(runnable)),
        "native_target_count": len(claimed),
        "runnable_evidence": dict(sorted(runnable.items())),
    }


def active_evidence(contract: Mapping[str, Any], qualification_profile: str) -> set[str]:
    """Select required producers without admitting deferred performance evidence."""

    if qualification_profile not in QUALIFICATION_PROFILES:
        raise harness.HarnessError(f"unsupported M5 qualification profile: {qualification_profile}")
    deferred = set(contract["qualification_profiles"][qualification_profile]["deferred_evidence"])
    return {name for record in contract["gates"] for name in record["evidence"]} - deferred


def gate_report(
    contract: Mapping[str, Any], summary: Mapping[str, Any], results: Mapping[str, Mapping[str, Any]],
    *, qualification_profile: str = "full",
) -> dict[str, Any]:
    """Classify each gate from reviewed blockers and executed evidence."""

    if qualification_profile not in QUALIFICATION_PROFILES:
        raise harness.HarnessError(f"unsupported M5 qualification profile: {qualification_profile}")
    active = active_evidence(contract, qualification_profile)
    results = {name: result for name, result in results.items() if name in active}
    records: list[dict[str, Any]] = []
    for gate in contract["gates"]:
        observed = {entry: results[entry]["status"] for entry in gate["evidence"] if entry in results}
        missing = [entry for entry in gate["evidence"] if entry not in summary["runnable_evidence"]]
        deferred = qualification_profile == "correctness" and gate["id"] == CORRECTNESS_DEFERRED_GATE
        if deferred:
            status = "deferred"
        elif any(status != "passed" for status in observed.values()):
            status = "failed"
        elif gate["blocked_by"] or missing or len(observed) != len(gate["evidence"]):
            status = "blocked"
        else:
            status = "passed"
        records.append({
            "blocked_by": list(gate["blocked_by"]),
            "evidence": observed,
            "id": gate["id"],
            "missing_evidence": missing,
            "status": status,
        })
    unmet = [record["id"] for record in records if record["status"] not in {"passed", "deferred"}]
    return {
        "contract": harness.relative(CONTRACT),
        "evidence": {key: dict(value) for key, value in sorted(results.items())},
        "gates": records,
        "overall_status": "passed" if not unmet else "unmet",
        "qualification_profile": qualification_profile,
        "performance_qualified": qualification_profile == "full" and not unmet
                                 and [record["id"] for record in records] == list(GATE_IDS),
        "deferred_gate_ids": [record["id"] for record in records
                              if qualification_profile == "correctness" and record["id"] == CORRECTNESS_DEFERRED_GATE],
        "unmet_required": unmet,
    }


def report_provenance(report: Mapping[str, Any]) -> dict[str, Any]:
    """Bind executed evidence to the checkout and its retained raw logs."""

    return {
        "git": engine.git_provenance(),
        "seal": {**integrated.source_seal(), "gate": engine.file_record(Path(__file__)),
                 "contract": engine.file_record(CONTRACT)},
        "evidence": {name: engine.file_record(harness.ROOT / record["log"])
                     for name, record in report["evidence"].items()},
    }


def read_report(path: Path | None = None, *, profile: str = "full") -> dict[str, Any]:
    """Read complete current functional evidence for the selected profile.

    Full qualification also replays the physical codegen audit. Correctness
    defers that audit and throughput without qualifying either as performance.
    """

    if profile not in QUALIFICATION_PROFILES:
        raise harness.HarnessError(f"unsupported M5 qualification profile: {profile}")
    artifacts = ARTIFACTS if profile == "full" else ARTIFACTS.with_name("m5-correctness-gate")
    path = artifacts / "report.json" if path is None else Path(path)
    try:
        if path.is_symlink() or not path.is_file() or path.resolve() != (artifacts / "report.json").resolve():
            raise harness.HarnessError("M5 report is absent or outside its profile directory")
        report = harness.read_json(path)
        import x86_64_m9_gate as audit_reader

        unmet = audit_reader.correctness_evidence_unmet(
            "m5", report, artifacts, None, qualification_profile=profile)
        if unmet:
            raise harness.HarnessError("M5 report is unmet: " + "; ".join(unmet))
        if profile == "correctness":
            return report
        import codegen_audit_x86_64 as codegen

        audit_path = codegen.REPORT_ROOT / "m5-gate.json"
        audit = harness.read_json(audit_path)
        unmet = audit_reader.codegen_unmet(audit, [scenario.name for scenario in codegen.SCENARIOS])
        inputs = audit["provenance"]["inputs"]
        source = dict(inputs, mimalloc={key: inputs["mimalloc"][key] for key in ("version", "tag", "revision")}
                      | {"archive_sha256": inputs["mimalloc"]["archive"]["sha256"]})
        products = audit_path.with_suffix(".artifacts")
        product_identity = {key: engine.sha256_file(products / name) for key, name in {
            "pinned_c_executable": "engine-fixture-pinned-c",
            "rust_engine_executable": "engine-fixture-rust-engine",
            "shared_fixture_object": "engine-fixture-c.o",
            "rust_engine_static_library": "libcrabc_allocator_engine_rust_backend.a",
        }.items()}
        unmet.extend(audit_reader.physical_codegen_unmet(audit_path, audit, codegen, {
            "identity": {"source": source, "configuration": {"tools": audit["provenance"]["tools"]}},
            "product_identity": product_identity,
        }))
        if unmet:
            raise harness.HarnessError("M5 structural audit is unmet: " + "; ".join(unmet))
        read_engine_early_proof()
        return report
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise harness.HarnessError(f"M5 report lacks current physical evidence: {error}") from error


def read_engine_early_proof() -> dict[str, float]:
    """Require the canonical qualified full matrix and its local wall bounds."""

    report_path = engine.REPORT_ROOT / "engine.json"
    try:
        bounds = engine.qualified_architecture_bounds(engine.ROOT, report_path)
    except (harness.HarnessError, engine.shared.HarnessError) as error:
        raise harness.HarnessError(f"M5 early engine proof report is invalid: {error}") from error
    for row_name, bound in bounds.items():
        if isinstance(bound, bool) or not isinstance(bound, (int, float)) or not math.isfinite(bound):
            raise harness.HarnessError(
                f"qualified engine row {row_name} has an invalid wall-throughput lower 95% bound"
            )
        if bound < EARLY_ENGINE_MINIMUM_LOWER_95:
            raise harness.HarnessError(
                f"qualified engine row {row_name} wall-throughput Rust/C lower 95% bound {bound:.6g} "
                f"is below the M5 floor {EARLY_ENGINE_MINIMUM_LOWER_95:.2f}"
            )
    return bounds


def check_receipt(check: Mapping[str, str], root: Path = harness.ROOT) -> tuple[bool, str]:
    """Validate one runner receipt; the message names its seal or its defect."""

    try:
        receipt = native_shadow_receipt.read_receipt(root, check["runner"], case_prefix=check["case_prefix"])
    except native_shadow_receipt.ReceiptError as error:
        return False, str(error)
    cases = receipt.case_ids(check["case_prefix"])
    return True, (
        f"{check['runner']}: {len(cases)} passing {check['case_prefix']!r} cases of "
        f"{len(receipt.cases)} at {receipt.source['revision']} "
        f"(worktree {receipt.source['worktree_sha256']}); {harness.relative(receipt.path)}\n"
        + "".join(f"  {case}\n" for case in cases)
    )


def run_evidence(runnable: Mapping[str, Any], artifacts: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for evidence_id, command in runnable.items():
        name = evidence_id.replace(":", "-")
        log = artifacts / f"{name}.log"
        if isinstance(command, Mapping):
            passed, message = check_receipt(command)
            log.write_text(message + "\n")
            results[evidence_id] = {
                "log": harness.relative(log),
                "receipt": dict(command),
                "status": "passed" if passed else "failed",
            }
            continue
        # Evidence that refuses to overwrite its own receipt gets a directory
        # that this gate run alone owns.
        scratch = artifacts / name
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True)
        command = [argument.replace(SCRATCH_PLACEHOLDER, str(scratch)) for argument in command]
        if is_native_test_group_command(command):
            status = run_native_helper_process(command, log)
            results[evidence_id] = {
                "command": list(command),
                "log": harness.relative(log),
                "status": "passed" if status == 0 else "failed",
            }
            continue
        record = harness.command_record(command, cwd=harness.ROOT, timeout_seconds=EVIDENCE_TIMEOUT_SECONDS)
        output = str(record["stdout"]) + str(record["stderr"])
        status = "passed" if record["status"] == 0 else "failed"
        log.write_text(output)
        results[evidence_id] = {
            "command": list(command),
            "log": harness.relative(log),
            "status": status,
        }
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
        help="validate the contract and native-target closure without executing evidence")
    mode.add_argument("--gate", choices=GATE_IDS,
        help="execute and classify only the evidence of one gate")
    mode.add_argument(INTERNAL_NATIVE_TEST_MODE, nargs="+", metavar="TARGET", help=argparse.SUPPRESS)
    mode.add_argument(INTERNAL_ENGINE_PROOF_MODE, action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--qualification-profile", choices=QUALIFICATION_PROFILES, default="full",
        help="correctness requires functional evidence and defers codegen optimization and throughput")
    arguments = parser.parse_args(argv)
    contract = harness.read_json(CONTRACT)
    summary = validate_contract(contract, harness.load_pin(), native_test_targets())
    if arguments.check:
        print(
            f"M5 gate contract valid: {summary['native_target_count']} native targets in "
            f"{len(summary['gate_ids'])} gates; {len(summary['blocked_gate_ids'])} gates blocked; "
            f"{len(summary['missing_evidence'])} evidence entries missing"
        )
        return 0
    harness.require_native_x86_64()
    if arguments.internal_native_tests is not None:
        issue = native_test_roster_issue(
            arguments.internal_native_tests,
            native_test_group_targets(summary["runnable_evidence"]),
        )
        if issue is not None:
            raise harness.HarnessError(f"M5 internal native test invocation is invalid: {issue}")
        status = run_native_test_helper(arguments.internal_native_tests, sys.stdout)
        if status != 0:
            print("M5 native target evidence failed", file=sys.stderr)
        return status
    if arguments.internal_engine_proof:
        bounds = read_engine_early_proof()
        report_path = harness.relative(engine.REPORT_ROOT / "engine.json")
        for row_name, bound in bounds.items():
            print(
                f"{report_path}: {row_name} wall-throughput Rust/C one-sided 95% lower bound "
                f"{bound:.6g} >= {EARLY_ENGINE_MINIMUM_LOWER_95:.2f}"
            )
        return 0
    artifacts = ARTIFACTS if arguments.qualification_profile == "full" else ARTIFACTS.with_name("m5-correctness-gate")
    artifacts.mkdir(parents=True, exist_ok=True)
    selected = contract
    runnable = summary["runnable_evidence"]
    if arguments.gate is not None:
        selected = dict(contract, gates=[gate for gate in contract["gates"] if gate["id"] == arguments.gate])
        wanted = set(selected["gates"][0]["evidence"])
        runnable = {key: value for key, value in runnable.items() if key in wanted}
    active = active_evidence(selected, arguments.qualification_profile)
    runnable = {key: value for key, value in runnable.items() if key in active}
    report = gate_report(selected, summary, run_evidence(runnable, artifacts),
                         qualification_profile=arguments.qualification_profile)
    report["provenance"] = report_provenance(report)
    harness.write_json(artifacts / "report.json", report)
    for record in report["gates"]:
        print(f"{record['id']}: {record['status']}")
    if report["overall_status"] != "passed":
        print(
            f"M5 unmet: {len(report['unmet_required'])}/{len(report['gates'])} required gates; "
            f"report {harness.relative(artifacts / 'report.json')}",
            file=sys.stderr,
        )
        return 1
    print("M5 passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except NativeProcessCancelled as error:
        print(f"ERROR: M5 gate interrupted: {error}", file=sys.stderr)
        sys.exit(128 + error.signum)
    except harness.HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
