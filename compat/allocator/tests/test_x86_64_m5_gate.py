#!/usr/bin/env python3
"""Contracts for the fail-closed native x86-64 allocator lifecycle gate."""

from __future__ import annotations

import copy
import ctypes
import importlib.util
import os
import select
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
SPEC = importlib.util.spec_from_file_location("x86_64_m5_gate", ROOT / "compat/allocator/x86_64_m5_gate.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)
harness = gate.harness


class M5GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pin = harness.load_pin()
        self.contract = harness.read_json(gate.CONTRACT)
        self.targets = gate.native_test_targets()

    def validate(self, contract=None, targets=None):
        return gate.validate_contract(
            self.contract if contract is None else contract,
            self.pin,
            self.targets if targets is None else targets,
        )

    def gate_record(self, contract, gate_id):
        return next(entry for entry in contract["gates"] if entry["id"] == gate_id)

    def test_checked_in_contract_claims_every_native_target_and_blocks_missing_evidence(self) -> None:
        summary = self.validate()
        self.assertEqual(summary["gate_ids"], list(gate.GATE_IDS))
        elsewhere = set(self.contract.get("native_tests_owned_elsewhere", {}))
        self.assertEqual(summary["native_target_count"], len(self.targets - elsewhere))
        missing = set(summary["missing_evidence"])
        for entry in self.contract["gates"]:
            if missing & set(entry["evidence"]):
                self.assertIn(entry["id"], summary["blocked_gate_ids"])

    def test_native_evidence_uses_the_internal_executor_for_a_checked_roster(self) -> None:
        targets = ["native_pointer_first_free", "native_live_remote_free"]
        command = gate.native_test_group_command(targets)
        self.assertEqual(command[:3], ["python3", "compat/allocator/x86_64_m5_gate.py", "--internal-native-tests"])
        self.assertEqual(command[3:], targets)
        for target in targets:
            target_command = gate.native_test_command(
                target, gate.native_test_feature_profiles(target)[0],
            )
            self.assertEqual(target_command[target_command.index("--test") + 1], target)
            self.assertEqual(
                target_command[target_command.index("--features") + 1], gate.NATIVE_FEATURES,
            )
            self.assertIn("--no-fail-fast", target_command)

    def test_native_evidence_helper_authority_contains_each_full_contract_roster(self) -> None:
        summary = self.validate()
        expected_rosters = {
            tuple(record["native_tests"])
            for record in self.contract["evidence"].values()
            if "native_tests" in record
        }
        self.assertEqual(
            {tuple(roster) for roster in gate.native_test_group_targets(summary["runnable_evidence"])},
            expected_rosters,
        )
        for evidence_id, record in self.contract["evidence"].items():
            if "native_tests" not in record:
                continue
            with self.subTest(evidence=evidence_id):
                command = summary["runnable_evidence"][evidence_id]
                self.assertEqual(command, gate.native_test_group_command(record["native_tests"]))
                self.assertEqual(command[3:], record["native_tests"])

    def test_native_evidence_helper_rejects_invalid_missing_extra_duplicate_and_wrong_targets(self) -> None:
        expected = ["native_first", "native_second"]
        rosters = [expected]
        self.assertIsNone(gate.native_test_roster_issue(expected, rosters))

        cases = (
            ([], "empty"),
            ([None], "invalid"),
            (["native_first"], "missing"),
            (["native_first", "native_second", "native_extra"], "extra"),
            (["native_first", "native_first"], "duplicate"),
            (["native_first", "native_wrong"], "roster"),
        )
        for targets, reason in cases:
            with self.subTest(targets=targets):
                self.assertIn(reason, gate.native_test_roster_issue(targets, rosters))

    def test_native_evidence_uses_live_helper_log_and_keeps_authoritative_argv(self) -> None:
        summary = self.validate()
        evidence_id = next(
            name for name, record in self.contract["evidence"].items() if "native_tests" in record
        )
        command = summary["runnable_evidence"][evidence_id]
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="m5-native-log-", dir=scratch) as temporary:
            artifacts = Path(temporary)

            def run_helper(observed_command, log):
                self.assertEqual(observed_command, command)
                log.write_text("completed target record\n")
                return 0

            with mock.patch.object(gate, "run_native_helper_process", side_effect=run_helper) as run:
                with mock.patch.object(gate.harness, "command_record") as command_record:
                    result = gate.run_evidence({evidence_id: command}, artifacts)[evidence_id]
                    log_text = (artifacts / f"{evidence_id.replace(':', '-')}.log").read_text()

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["command"], command)
        self.assertIn("completed target record", log_text)
        run.assert_called_once()
        command_record.assert_not_called()

    def test_native_target_validation_uses_the_final_parent_summary(self) -> None:
        child_summary = (
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        )
        parent_pass = (
            "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        )
        passing = {"status": 0, "stdout": child_summary * 4 + parent_pass, "stderr": "native warning\n"}
        self.assertIsNone(gate.native_test_run_issue("native_parent", passing))

        parent_zero = (
            "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        )
        self.assertIn("no successful tests", gate.native_test_run_issue(
            "native_parent", {"status": 0, "stdout": child_summary + parent_zero, "stderr": ""}
        ))

        parent_failed = (
            "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        )
        self.assertIn("did not finish", gate.native_test_run_issue(
            "native_parent", {"status": 0, "stdout": child_summary + parent_failed, "stderr": "child failed\n"}
        ))
        self.assertIn("no parent test summary", gate.native_test_run_issue(
            "native_parent", {"status": 0, "stdout": "", "stderr": ""}
        ))
        self.assertIn("exited with status 101", gate.native_test_run_issue(
            "native_parent", {"status": 101, "stdout": parent_pass, "stderr": "late Cargo failure\n"}
        ))
        self.assertIn("runtime limit", gate.native_test_run_issue(
            "native_parent", {"status": 124, "stdout": "", "stderr": "", "timed_out": True}
        ))

    def test_native_target_runs_preserve_streams_and_continue_after_a_failed_target(self) -> None:
        passed = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        failed = "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        targets = ["native_first", "native_second"]
        owner = mock.Mock()

        def run(command, *, timeout_seconds):
            target = command[command.index("--test") + 1]
            if "--no-run" in command:
                return {"status": 0, "stdout": f"{target} build output\n", "stderr": "build stderr\n"}
            if target == targets[0]:
                return {"status": 101, "stdout": passed + failed, "stderr": "first stderr\n"}
            return {"status": 0, "stdout": passed, "stderr": "second stderr\n"}

        owner.run.side_effect = run
        status, log = gate.execute_native_test_group(targets, process_helper=owner)
        self.assertEqual(status, 1)
        self.assertEqual(owner.run.call_count, 4)
        self.assertEqual(
            [call.kwargs["timeout_seconds"] for call in owner.run.call_args_list],
            [None, gate.EVIDENCE_TIMEOUT_SECONDS, None, gate.EVIDENCE_TIMEOUT_SECONDS],
        )
        self.assertIn("first stderr\n", log)
        self.assertIn("second stderr\n", log)
        self.assertIn("test result: FAILED", log)
        self.assertIn("build output", log)
        self.assertIn("exit status: 101", log)
        self.assertIn("exit status: 0", log)

    def test_secure_native_targets_run_with_features_that_activate_their_tests(self) -> None:
        secure_growth = gate.native_test_feature_profiles("native_secure_public_growth")
        self.assertEqual(
            secure_growth,
            (
                (*gate.NATIVE_FEATURES.split(","), "mi-secure-3"),
                (*gate.NATIVE_FEATURES.split(","), "mi-guarded"),
            ),
        )
        secure_release = gate.native_test_feature_profiles("native_secure_os_release_lifecycle")
        self.assertEqual(
            secure_release,
            ((*gate.NATIVE_FEATURES.split(","), "mi-secure-5"),),
        )
        self.assertEqual(
            gate.native_test_feature_profiles("native_pointer_first_free"),
            (tuple(gate.NATIVE_FEATURES.split(",")),),
        )

    def test_secure_native_targets_each_run_in_their_own_feature_profile(self) -> None:
        targets = ["native_secure_public_growth", "native_secure_os_release_lifecycle"]
        passed = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        owner = mock.Mock()

        def run(command, *, timeout_seconds):
            if "--no-run" in command:
                return {"status": 0, "stdout": "", "stderr": ""}
            return {"status": 0, "stdout": passed, "stderr": "target stderr\n"}

        owner.run.side_effect = run
        status, log = gate.execute_native_test_group(targets, process_helper=owner)
        self.assertEqual(status, 0)
        self.assertEqual(owner.run.call_count, 6)
        commands = [call.args[0] for call in owner.run.call_args_list if "--no-run" not in call.args[0]]
        self.assertEqual(
            [(command[command.index("--test") + 1], command[command.index("--features") + 1])
             for command in commands],
            [
                (targets[0], ",".join(gate.native_test_feature_profiles(targets[0])[0])),
                (targets[0], ",".join(gate.native_test_feature_profiles(targets[0])[1])),
                (targets[1], ",".join(gate.native_test_feature_profiles(targets[1])[0])),
            ],
        )
        self.assertTrue(all(call.kwargs["timeout_seconds"] is None for call in owner.run.call_args_list[::2]))
        self.assertTrue(all(
            call.kwargs["timeout_seconds"] == gate.EVIDENCE_TIMEOUT_SECONDS
            for call in owner.run.call_args_list[1::2]
        ))
        self.assertEqual(log.count("target stderr\n"), 3)

    def _native_ready_child(self, temporary_path: Path) -> tuple[list[str], int, Path, Path]:
        ready_fifo = temporary_path / "ready"
        marker = temporary_path / "terminated"
        mask = temporary_path / "sigterm-mask"
        os.mkfifo(ready_fifo)
        ready_fd = os.open(ready_fifo, os.O_RDWR | os.O_NONBLOCK)
        script = f"""
import os, signal
from pathlib import Path
blocked = signal.SIGTERM in signal.pthread_sigmask(signal.SIG_BLOCK, set())
Path({str(mask)!r}).write_text("blocked" if blocked else "unblocked")
def stop(_signum, _frame):
    Path({str(marker)!r}).write_text("handled")
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
fd = os.open({str(ready_fifo)!r}, os.O_WRONLY)
os.write(fd, b"ready")
os.close(fd)
signal.pause()
"""
        return [sys.executable, "-c", script], ready_fd, marker, mask

    def _signal_at_popen_return(self, ready_fd: int, processes: list[subprocess.Popen]):
        real_popen = subprocess.Popen

        def spawn(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            processes.append(process)
            readable, _, _ = select.select([ready_fd], [], [], 10)
            if not readable:
                raise AssertionError("native child did not reach the Popen publication barrier")
            if os.read(ready_fd, 64) != b"ready":
                raise AssertionError("native child sent an invalid readiness marker")
            os.kill(os.getpid(), signal.SIGTERM)
            return process

        return spawn

    def _kill_unreaped_processes(self, processes: list[subprocess.Popen], ready_fd: int) -> None:
        os.close(ready_fd)
        for process in processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()

    @unittest.skipUnless(sys.platform.startswith("linux"), "native process cleanup uses Linux process groups")
    def test_native_process_helper_owns_child_before_delivering_cancellation(self) -> None:
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="m5-popen-owner-", dir=scratch) as temporary:
            command, ready_fd, marker, mask = self._native_ready_child(Path(temporary))
            processes = []
            reaped_by_owner = False
            cancellation = gate._install_cancellation_handlers()
            owner = gate.NativeProcessHelper(cancellation)
            try:
                with mock.patch.object(
                    gate.subprocess, "Popen",
                    side_effect=self._signal_at_popen_return(ready_fd, processes),
                ):
                    with self.assertRaises(gate.NativeProcessCancelled) as cancelled:
                        owner.run(command, timeout_seconds=None)
            finally:
                reaped_by_owner = len(processes) == 1 and processes[0].poll() is not None
                self._kill_unreaped_processes(processes, ready_fd)
                gate._restore_signal_handlers(cancellation.previous)

            self.assertEqual(cancelled.exception.signum, signal.SIGTERM)
            self.assertEqual(len(processes), 1)
            self.assertTrue(reaped_by_owner)
            self.assertIsNotNone(processes[0].returncode)
            self.assertEqual(mask.read_text(), "unblocked")
            self.assertEqual(marker.read_text(), "handled")

    @unittest.skipUnless(sys.platform.startswith("linux"), "native process cleanup uses Linux process groups")
    def test_live_helper_owns_child_before_delivering_cancellation(self) -> None:
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="m5-popen-helper-", dir=scratch) as temporary:
            temporary_path = Path(temporary)
            command, ready_fd, marker, mask = self._native_ready_child(temporary_path)
            log = temporary_path / "native-helper.log"
            processes = []
            reaped_by_owner = False
            try:
                with mock.patch.object(
                    gate.subprocess, "Popen",
                    side_effect=self._signal_at_popen_return(ready_fd, processes),
                ):
                    with self.assertRaises(gate.NativeProcessCancelled) as cancelled:
                        gate.run_native_helper_process(command, log)
            finally:
                reaped_by_owner = len(processes) == 1 and processes[0].poll() is not None
                self._kill_unreaped_processes(processes, ready_fd)

            self.assertEqual(cancelled.exception.signum, signal.SIGTERM)
            self.assertEqual(len(processes), 1)
            self.assertTrue(reaped_by_owner)
            self.assertIsNotNone(processes[0].returncode)
            self.assertEqual(mask.read_text(), "unblocked")
            self.assertEqual(marker.read_text(), "handled")

    @unittest.skipUnless(sys.platform.startswith("linux"), "native process cleanup uses Linux subreaping")
    def test_native_helper_signal_reaps_active_descendants_and_keeps_completed_records(self) -> None:
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        libc = ctypes.CDLL(None, use_errno=True)
        previous_subreaper = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous_subreaper), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(gate.PR_SET_CHILD_SUBREAPER, ctypes.c_ulong(1), 0, 0, 0), 0)

        try:
            with tempfile.TemporaryDirectory(prefix="m5-native-process-", dir=scratch) as temporary:
                temporary_path = Path(temporary)
                ready_fifo = temporary_path / "ready"
                terminated_prefix = temporary_path / "terminated"
                log = temporary_path / "native-evidence.log"
                os.mkfifo(ready_fifo)
                ready_fd = os.open(ready_fifo, os.O_RDWR | os.O_NONBLOCK)
                second_target = f"""
import os, signal
fifo = {str(ready_fifo)!r}
log = {str(log)!r}
marker = {str(terminated_prefix)!r}
with open(log) as output:
    assert "=== native target native_waiting" in output.read()
def stop(_signum, _frame):
    with open(marker + "." + str(os.getpid()), "w") as output:
        output.write("terminated")
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
child = os.fork()
if child == 0:
    signal.pause()
fd = os.open(fifo, os.O_WRONLY)
os.write(fd, (str(os.getpid()) + " " + str(child) + "\\n").encode())
os.close(fd)
signal.pause()
"""
                first_target = (
                    "print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                    "0 filtered out; finished in 0.00s')"
                )
                driver = f"""
import sys
sys.path.insert(0, {str(ROOT / "compat/allocator")!r})
import x86_64_m5_gate as gate
gate.native_test_feature_profiles = lambda _target: (("test",),)
gate.native_test_command = lambda target, _features: [
    sys.executable, "-c", {first_target!r} if target == "native_first" else {second_target!r}
]
raise SystemExit(gate.run_native_test_helper(
    ["native_first", "native_waiting"], sys.stdout,
))
"""
                controller_result = {}

                def interrupt_after_target_starts() -> None:
                    try:
                        readable, _, _ = select.select([ready_fd], [], [], 10)
                        if not readable:
                            raise AssertionError("native child did not reach the cancellation barrier")
                        controller_result["pids"] = [int(pid) for pid in os.read(ready_fd, 128).split()]
                        if len(controller_result["pids"]) != 2:
                            raise AssertionError("native child did not report both process ids")
                        controller_result["pgid"] = os.getpgid(controller_result["pids"][1])
                        controller_result["log_before_signal"] = log.read_text()
                    except BaseException as error:
                        controller_result["error"] = str(error)
                    finally:
                        os.kill(os.getpid(), signal.SIGTERM)

                controller = threading.Thread(target=interrupt_after_target_starts, daemon=True)
                controller.start()
                try:
                    with self.assertRaises(gate.NativeProcessCancelled) as cancelled:
                        gate.run_native_helper_process([sys.executable, "-c", driver], log)
                finally:
                    controller.join(timeout=10)
                    os.close(ready_fd)
                    pgid = controller_result.get("pgid")
                    if pgid is not None:
                        try:
                            os.killpg(pgid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        while True:
                            try:
                                os.waitpid(-pgid, 0)
                            except InterruptedError:
                                continue
                            except ChildProcessError:
                                break

                self.assertFalse(controller.is_alive())
                self.assertNotIn("error", controller_result)
                self.assertEqual(cancelled.exception.signum, signal.SIGTERM)
                log_text = controller_result["log_before_signal"]
                self.assertIn("=== native target native_first", log_text)
                self.assertIn("--- validation ---\npassed", log_text)
                self.assertIn("=== native target native_waiting", log_text)
                for pid in controller_result["pids"]:
                    self.assertTrue((temporary_path / f"terminated.{pid}").is_file())
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
        finally:
            self.assertEqual(
                libc.prctl(
                    gate.PR_SET_CHILD_SUBREAPER, ctypes.c_ulong(previous_subreaper.value), 0, 0, 0,
                ),
                0,
            )

    def test_a_new_native_target_outside_every_evidence_entry_breaks_closure(self) -> None:
        with self.assertRaisesRegex(harness.HarnessError, "native_future_witness"):
            self.validate(targets=self.targets | {"native_future_witness"})

    def test_a_doubly_claimed_or_absent_native_target_is_rejected(self) -> None:
        doubled = copy.deepcopy(self.contract)
        target = doubled["evidence"]["native:pointer-dispatch"]["native_tests"][0]
        doubled["evidence"]["native:generic-exit"]["native_tests"].append(target)
        with self.assertRaisesRegex(harness.HarnessError, "claimed by both"):
            self.validate(doubled)

        absent = copy.deepcopy(self.contract)
        absent["evidence"]["native:generic-exit"]["native_tests"].append("native_not_a_target")
        with self.assertRaisesRegex(harness.HarnessError, "absent native target"):
            self.validate(absent)

    def test_a_target_owned_elsewhere_must_be_cited_by_that_gate(self) -> None:
        uncited = copy.deepcopy(self.contract)
        target = uncited["evidence"]["native:pointer-dispatch"]["native_tests"].pop()
        uncited["native_tests_owned_elsewhere"] = {target: "compat/allocator/x86_64_m7_gate.py"}
        with self.assertRaisesRegex(harness.HarnessError, "does not cite it"):
            self.validate(uncited)

    def test_missing_evidence_requires_a_reviewed_blocker(self) -> None:
        unblocked = copy.deepcopy(self.contract)
        self.gate_record(unblocked, "m5.codegen-performance")["blocked_by"] = []
        with self.assertRaisesRegex(harness.HarnessError, "missing evidence without a blocker"):
            self.validate(unblocked)

    def test_malformed_evidence_or_gate_identity_is_rejected(self) -> None:
        both = copy.deepcopy(self.contract)
        both["evidence"]["differential:reclaim-on-free"]["native_tests"] = ["native_reclaim_on_free"]
        with self.assertRaisesRegex(harness.HarnessError, "exactly native_tests, command, or receipt"):
            self.validate(both)

        absent_runner = copy.deepcopy(self.contract)
        absent_runner["evidence"]["differential:reclaim-on-free"]["command"] = [
            "python3", "compat/allocator/not_a_runner.py",
        ]
        with self.assertRaisesRegex(harness.HarnessError, "absent runner"):
            self.validate(absent_runner)

        reordered = copy.deepcopy(self.contract)
        reordered["gates"].reverse()
        with self.assertRaisesRegex(harness.HarnessError, "order or identity"):
            self.validate(reordered)

        malformed = copy.deepcopy(self.contract)
        malformed["evidence"]["receipt:seeded-soak"]["receipt"] = {"runner": "../escape", "case_prefix": "soak-"}
        with self.assertRaisesRegex(harness.HarnessError, "malformed receipt check"):
            self.validate(malformed)

        unused = copy.deepcopy(self.contract)
        unused["evidence"]["differential:unused"] = {"command": None, "scope": "unused"}
        with self.assertRaisesRegex(harness.HarnessError, "declared but unused"):
            self.validate(unused)

    def test_report_fails_on_any_failed_evidence_and_blocks_on_blockers_or_missing_runs(self) -> None:
        summary = self.validate()
        passed = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        report = gate.gate_report(self.contract, summary, passed)
        by_id = {record["id"]: record["status"] for record in report["gates"]}
        for entry in self.contract["gates"]:
            expected = "blocked" if entry["id"] in summary["blocked_gate_ids"] else "passed"
            self.assertEqual(by_id[entry["id"]], expected, entry["id"])
        self.assertEqual(report["overall_status"], "unmet")

        failed = dict(passed, **{"ratchet:architecture": {"status": "failed"}})
        report = gate.gate_report(self.contract, summary, failed)
        by_id = {record["id"]: record["status"] for record in report["gates"]}
        self.assertEqual(by_id["m5.pointer-dispatch"], "failed")
        self.assertEqual(by_id["m5.no-forbidden-scaffolding"], "failed")

        not_run = {key: value for key, value in passed.items() if key != "native:generic-exit"}
        report = gate.gate_report(self.contract, summary, not_run)
        self.assertEqual(
            next(record for record in report["gates"] if record["id"] == "m5.generic-exit")["status"],
            "blocked",
        )

    def test_two_publisher_owner_exit_differential_is_required(self) -> None:
        evidence_id = "differential:owner-exit-late-remote-two-producers"
        summary = self.validate()
        self.assertIn(evidence_id, summary["runnable_evidence"])
        records = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        records[evidence_id] = {"status": "failed"}
        report = gate.gate_report(self.contract, summary, records)
        generic_exit = next(entry for entry in report["gates"] if entry["id"] == "m5.generic-exit")
        self.assertEqual(generic_exit["status"], "failed")

    def test_correctness_profile_retains_functional_evidence_and_defers_performance(self) -> None:
        summary = self.validate()
        records = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]
                   if entry not in {"codegen:hot-path-audit", "perf:engine-early-proof"}}
        report = gate.gate_report(self.contract, summary, records, qualification_profile="correctness")
        self.assertEqual(report["qualification_profile"], "correctness")
        self.assertFalse(report["performance_qualified"])
        self.assertEqual(report["deferred_gate_ids"], ["m5.codegen-performance"])
        self.assertEqual(report["overall_status"], "passed")
        self.assertEqual(report["unmet_required"], [])
        statuses = {entry["id"]: entry["status"] for entry in report["gates"]}
        self.assertEqual(statuses.pop("m5.codegen-performance"), "deferred")
        self.assertEqual(set(statuses.values()), {"passed"})
        self.assertEqual(set(report["evidence"]), set(records))
        full = gate.gate_report(self.contract, summary, records)
        self.assertEqual(full["qualification_profile"], "full")
        self.assertEqual(full["deferred_gate_ids"], [])
        self.assertEqual(full["overall_status"], "unmet")

    def test_correctness_profile_requires_every_functional_observation(self) -> None:
        summary = self.validate()
        passed = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        for evidence_id in set(passed) - {"codegen:hot-path-audit", "perf:engine-early-proof"}:
            with self.subTest(evidence=evidence_id):
                failed = dict(passed, **{evidence_id: {"status": "failed"}})
                report = gate.gate_report(self.contract, summary, failed, qualification_profile="correctness")
                self.assertEqual(report["overall_status"], "unmet")
                absent = {name: value for name, value in passed.items() if name != evidence_id}
                report = gate.gate_report(self.contract, summary, absent, qualification_profile="correctness")
                self.assertEqual(report["overall_status"], "unmet")

    def test_unknown_qualification_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(harness.HarnessError, "qualification profile"):
            gate.gate_report(self.contract, self.validate(), {}, qualification_profile="subset")
        weakened = copy.deepcopy(self.contract)
        weakened["qualification_profiles"]["correctness"]["deferred_evidence"].append("ratchet:architecture")
        with self.assertRaisesRegex(harness.HarnessError, "defer only"):
            self.validate(weakened)

    def test_correctness_cli_executes_only_functional_evidence_in_a_separate_report_directory(self) -> None:
        summary = self.validate()
        records = {entry: {"status": "passed"} for entry in summary["runnable_evidence"]}
        with mock.patch.object(gate.harness, "require_native_x86_64"), \
                mock.patch.object(gate.Path, "mkdir"), \
                mock.patch.object(gate, "run_evidence", return_value=records) as execute, \
                mock.patch.object(gate, "report_provenance", return_value={}), \
                mock.patch.object(gate.harness, "write_json") as write:
            self.assertEqual(gate.main(["--qualification-profile", "correctness"]), 0)
        active = {name: command for name, command in summary["runnable_evidence"].items()
                  if name not in {"codegen:hot-path-audit", "perf:engine-early-proof"}}
        execute.assert_called_once_with(active, gate.ARTIFACTS.with_name("m5-correctness-gate"))
        self.assertEqual(write.call_args.args[0], gate.ARTIFACTS.with_name("m5-correctness-gate") / "report.json")
        report = write.call_args.args[1]
        import x86_64_m9_gate as full_reader
        report["provenance"] = {}
        self.assertIn("report lacks the complete passing gate roster", full_reader.correctness_evidence_unmet(
            "m5", report, gate.ARTIFACTS, None))

    def test_correctness_reader_requires_functional_authenticity_without_codegen_replay(self) -> None:
        import x86_64_m9_gate as audit_reader
        scratch = ROOT / ".work/allocator-x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            artifacts = Path(temporary) / "m5-correctness-gate"
            artifacts.mkdir()
            report_path = artifacts / "report.json"
            report_path.write_text("{}")
            report = {"qualification_profile": "correctness"}
            def read(path):
                if path == report_path:
                    return report
                raise FileNotFoundError(path)

            with mock.patch.object(gate, "ARTIFACTS", artifacts.with_name("m5-gate")), \
                    mock.patch.object(gate.harness, "read_json", side_effect=read) as read_json, \
                    mock.patch.object(audit_reader, "correctness_evidence_unmet", return_value=[]) as classify, \
                    mock.patch.object(audit_reader, "physical_codegen_unmet") as replay:
                self.assertEqual(gate.read_report(profile="correctness"), report)
                classify.assert_called_once_with("m5", report, artifacts, None, qualification_profile="correctness")
                read_json.assert_called_once_with(report_path)
                replay.assert_not_called()
                classify.return_value = ["report lacks current clean source"]
                with self.assertRaisesRegex(harness.HarnessError, "current clean source"):
                    gate.read_report(profile="correctness")
                classify.return_value = []
                full_path = artifacts.with_name("m5-gate") / "report.json"
                full_path.parent.mkdir()
                full_path.write_text("{}")
                report_path = full_path
                with self.assertRaisesRegex(harness.HarnessError, "physical evidence"):
                    gate.read_report(profile="full")

    def test_receipt_evidence_is_runnable_and_passes_only_on_a_valid_receipt(self) -> None:
        summary = self.validate()
        for evidence_id in ("receipt:libc-shadow-pthread-teardown", "receipt:upstream-test-stress",
                            "receipt:seeded-soak"):
            self.assertIn(evidence_id, summary["runnable_evidence"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / ".gitignore").write_text(".work/\n")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t",
                            "commit", "-qm", "base"], cwd=root, check=True)
            check = {"runner": "owned-native-allocator-stress", "case_prefix": "soak-"}
            passed, message = gate.check_receipt(check, root)
            self.assertFalse(passed)
            self.assertIn("no receipt", message)
            work = root / ".work/x86_64/tmp/run"
            work.mkdir(parents=True)
            (work / "soak.stdout").write_text("summary\n")
            gate.native_shadow_receipt.write_receipt(
                root, check["runner"], work, {"soak-static-pie": work / "soak.stdout"},
                [("soak-1-static-pie", 0, [work / "soak.stdout"])], {}, True,
            )
            passed, message = gate.check_receipt(check, root)
            self.assertTrue(passed, message)
            passed, message = gate.check_receipt(dict(check, case_prefix="stress-"), root)
            self.assertFalse(passed)


if __name__ == "__main__":
    unittest.main()
