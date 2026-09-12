"""Focused lifecycle and retention tests for the native C-performance runner."""

from __future__ import annotations

import importlib.util
import errno
import os
import signal
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[3]
WORK_ROOT = ROOT / ".work/x86_64"
WORK_ROOT.mkdir(parents=True, exist_ok=True)
MODULE = ROOT / "compat/perf/run_x86_64.py"
SPEC = importlib.util.spec_from_file_location("crabc_perf_x86_runner", MODULE)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class TraceeWaitTests(unittest.TestCase):
    def test_trace_diagnostic_command_uses_fixed_strace_not_path_lookup(self) -> None:
        with patch.dict(os.environ, {"PATH": "/shadow"}, clear=False), \
             patch.object(runner.shutil, "which", return_value="/shadow/strace"):
            command = runner.fixed_strace_attach_command(Path("/trace.raw"), 123)
        self.assertEqual(command[0], runner.evidence.FIXED_STRACE)
        self.assertEqual(command[-2:], ["-p", "123"])

    def test_preexec_wait_uses_nonblocking_waitpid_and_times_out(self) -> None:
        started = time.monotonic()
        with patch.object(runner.os, "waitpid", return_value=(0, 0)) as waited, \
             patch.object(runner.time, "sleep", return_value=None):
            with self.assertRaisesRegex(runner.CgroupUnsupported, "timed out"):
                runner.waitpid_until(12345, time.monotonic() + 0.005, phase="regression")
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertTrue(waited.called)
        self.assertTrue(all(call.args[1] & os.WNOHANG for call in waited.call_args_list))

    def test_timed_child_timeout_kills_and_reaps_exact_child(self) -> None:
        pid = os.fork()
        if pid == 0:
            signal.pause()
            os._exit(127)
        status, _usage, timed_out = runner.wait_child(pid, 0.01)
        self.assertTrue(timed_out)
        self.assertTrue(os.WIFSIGNALED(status))
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)

    def test_stalled_preexec_tracee_is_bounded_and_reaped(self) -> None:
        """A denied/stalled ptrace path cannot strand its stopped child."""

        pid = os.fork()
        if pid == 0:
            signal.pause()
            os._exit(127)
        session = SimpleNamespace()
        started = time.monotonic()
        with self.assertRaisesRegex(runner.CgroupUnsupported, "timed out"):
            runner.ptrace_until_preexec(
                pid, session, WORK_ROOT / "unused-probe", ROOT, 0.01,
                expected_binary="/app/bin/workload", expected_arguments=["allocator_live", "128", "262144", "97", "98"],
            )
        self.assertLess(time.monotonic() - started, 1.0)
        with self.assertRaises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)


class TimingLauncherLifecycleTests(unittest.TestCase):
    def test_abnormal_supervisor_exit_kills_its_surviving_process_group(self) -> None:
        """A dead launcher leader cannot leave an unmeasured workload alive."""

        row = next(item for item in runner.performance_rows(ROOT) if item.name == "memmem_guard63")
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            lane_root = directory / "lane"
            lane_root.mkdir()
            child_pid = directory / "surviving-child.pid"
            supervisor = directory / "abnormal-supervisor.py"
            supervisor.write_text(
                "#!/usr/bin/env python3\n"
                "import os, pathlib, signal, time\n"
                f"marker = pathlib.Path({str(child_pid)!r})\n"
                "pid = os.fork()\n"
                "if pid == 0:\n"
                "    os.close(1)\n"
                "    os.close(2)\n"
                "    while True:\n"
                "        time.sleep(1)\n"
                "marker.write_text(str(pid), encoding='ascii')\n"
                "os._exit(7)\n",
                encoding="utf-8",
            )
            supervisor.chmod(0o755)
            lane = runner.Lane(
                name="musl", root=lane_root,
                binaries={row.timed_artifact: "/app/bin/fake"}, dsos={},
                io_file=directory / "io", span_inputs={},
                environment={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            )
            launcher = runner.TimingLauncher(
                source=supervisor, output=supervisor, command=[], raw={},
            )
            result = runner.run_timed(
                ROOT, lane, row, directory / "attempt", 1.0, launcher,
                client_cpu=2, peer_cpu=None, allowed_affinity=(2,),
            )
            self.assertEqual(result["status"]["kind"], "launcher-failed")
            self.assertEqual(result["launcher"]["status"], {"kind": "exit", "code": 7})
            deadline = time.monotonic() + 2.0
            while not child_pid.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(child_pid.exists(), "test supervisor never recorded its child")
            pid = int(child_pid.read_text(encoding="ascii"))
            try:
                while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(Path(f"/proc/{pid}").exists(), "surviving launcher child was not killed")
            finally:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_zero_exit_without_result_kills_its_surviving_process_group(self) -> None:
        """A zero-exit supervisor without a result is still an abnormal abort."""

        row = next(item for item in runner.performance_rows(ROOT) if item.name == "memmem_guard63")
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            lane_root = directory / "lane"
            lane_root.mkdir()
            child_pid = directory / "surviving-child.pid"
            supervisor = directory / "zero-exit-no-result.py"
            supervisor.write_text(
                "#!/usr/bin/env python3\n"
                "import os, pathlib, time\n"
                f"marker = pathlib.Path({str(child_pid)!r})\n"
                "pid = os.fork()\n"
                "if pid == 0:\n"
                "    os.close(1)\n"
                "    os.close(2)\n"
                "    while True:\n"
                "        time.sleep(1)\n"
                "marker.write_text(str(pid), encoding='ascii')\n"
                "os._exit(0)\n",
                encoding="utf-8",
            )
            supervisor.chmod(0o755)
            lane = runner.Lane(
                name="musl", root=lane_root,
                binaries={row.timed_artifact: "/app/bin/fake"}, dsos={},
                io_file=directory / "io", span_inputs={},
                environment={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            )
            launcher = runner.TimingLauncher(
                source=supervisor, output=supervisor, command=[], raw={},
            )
            result = runner.run_timed(
                ROOT, lane, row, directory / "attempt", 1.0, launcher,
                client_cpu=2, peer_cpu=None, allowed_affinity=(2,),
            )
            self.assertEqual(result["status"]["kind"], "launcher-failed")
            self.assertEqual(result["launcher"]["status"], {"kind": "exit", "code": 0})
            self.assertIn("no result JSON", result["status"]["reason"])
            deadline = time.monotonic() + 2.0
            while not child_pid.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(child_pid.exists(), "test supervisor never recorded its child")
            pid = int(child_pid.read_text(encoding="ascii"))
            try:
                while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(Path(f"/proc/{pid}").exists(), "zero-exit launcher child was not killed")
            finally:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


class MeasurementCompletenessTests(unittest.TestCase):
    def test_red_syscall_scorecard_is_complete_when_clients_and_raw_diagnostics_exist(self) -> None:
        """A replayable red verdict must not be relabelled as missing data."""

        complete_red = {
            "startup": {
                "comparison": {
                    "status": "ok",
                    "syscall_gate": {"status": "fail", "violations": ["whole_process: excess calls"]},
                },
                "musl": {"syscalls": {"status": "ok"}},
                "crabc": {"syscalls": {"status": "ok"}},
            },
        }
        self.assertTrue(runner.timed_measurements_are_complete(complete_red))
        incomplete = {
            **complete_red,
            "broken": {
                "comparison": {"status": "ok", "syscall_gate": {"status": "pass"}},
                "musl": {"syscalls": {"status": "ok"}},
                "crabc": {"syscalls": {"status": "failed"}},
            },
        }
        self.assertFalse(runner.timed_measurements_are_complete(incomplete))


class DescriptorClosureTests(unittest.TestCase):
    def test_descriptor_closure_uses_fixed_kernel_ranges(self) -> None:
        """Child setup cannot turn a high RLIMIT into one close per number."""

        calls: list[tuple[int, int]] = []
        with patch.object(runner, "_kernel_close_range", side_effect=lambda first, last: calls.append((first, last))), \
             patch.object(runner.resource, "getrlimit", side_effect=AssertionError("RLIMIT sweep is forbidden")), \
             patch.object(runner.os, "closerange", side_effect=AssertionError("per-descriptor close is forbidden")):
            runner.close_inherited_descriptors({0, 1, 2, 97, 98})

        self.assertEqual(calls, [(3, 96), (99, runner.CLOSE_RANGE_LAST)])

    def test_kernel_ranges_close_a_high_inherited_descriptor(self) -> None:
        """The fixed-range path closes real inherited descriptors in a child."""

        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read_fd)
                source = os.open("/dev/null", os.O_RDONLY)
                try:
                    inherited = os.dup2(source, 131_072)
                finally:
                    if source != 131_072:
                        os.close(source)
                runner.close_inherited_descriptors({0, 1, 2, write_fd})
                try:
                    os.fstat(inherited)
                except OSError as error:
                    outcome = b"closed" if error.errno == errno.EBADF else b"wrong-error"
                else:
                    outcome = b"still-open"
                os.write(write_fd, outcome)
            finally:
                os._exit(0)
        os.close(write_fd)
        try:
            self.assertEqual(os.read(read_fd, 32), b"closed")
            waited, status = os.waitpid(pid, 0)
            self.assertEqual(waited, pid)
            self.assertTrue(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0)
        finally:
            os.close(read_fd)


class RetentionTests(unittest.TestCase):
    def test_umask_077_retention_is_readable_before_seal(self) -> None:
        old_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
                root = Path(temporary)
                nested = root / "nested" / "artifact"
                nested.parent.mkdir()
                nested.write_text("retained\n", encoding="utf-8")
                # TemporaryDirectory may inherit an enclosing setgid bit;
                # establish the exact 077-created ordinary modes this
                # regression is meant to normalize.
                os.chmod(root, 0o700)
                os.chmod(nested.parent, 0o700)
                os.chmod(nested, 0o600)
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(nested.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(nested.stat().st_mode), 0o600)
                runner.normalize_retained_path(ROOT, nested)
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE(nested.parent.stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE(nested.stat().st_mode), 0o644)
                identity = runner.retained_identity(ROOT, nested)
                self.assertEqual(identity["path"], "/workspace/" + nested.relative_to(ROOT).as_posix())
                runner.normalize_retained_path(ROOT, nested)
                self.assertEqual(runner.retained_identity(ROOT, nested), identity)
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE(nested.parent.stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE(nested.stat().st_mode), 0o644)
        finally:
            os.umask(old_umask)


class ImageToolManifestEnvironmentTests(unittest.TestCase):
    @unittest.skipUnless(runner.IMAGE_TOOL_MANIFEST.is_file(), "pinned native performance image only")
    def test_image_manifest_binds_the_image_owned_tools(self) -> None:
        """The Docker-built manifest is usable as a retained replay input."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            retained = Path(temporary) / "image-tools.manifest"
            manifest = runner.capture_image_tool_manifest(ROOT, retained)
            expected = {
                runner.DEFAULT_MUSL_CC: runner.external_tool_identity(Path(runner.DEFAULT_MUSL_CC))["sha256"],
                runner.evidence.FIXED_READELF: runner.external_tool_identity(Path(runner.evidence.FIXED_READELF))["sha256"],
                runner.evidence.FIXED_STRACE: runner.external_tool_identity(Path(runner.evidence.FIXED_STRACE))["sha256"],
                # The pinned musl loader is a compatibility symlink to libc.
                # Its oracle record intentionally keeps the loader pathname
                # while sealing the resolved file bytes.
                runner.evidence.FIXED_MUSL_LOADER: runner.external_tool_identity(Path(runner.evidence.FIXED_MUSL_LOADER))["sha256"],
                runner.evidence.FIXED_MUSL_LIBC: runner.external_tool_identity(Path(runner.evidence.FIXED_MUSL_LIBC))["sha256"],
            }
            self.assertEqual(manifest["tools"], expected)
            self.assertTrue(retained.is_file())


class HostIdentityTests(unittest.TestCase):
    def test_cpu_identity_ignores_live_frequency_telemetry(self) -> None:
        """A normal CPU-frequency change cannot invalidate one attempt."""

        before = (
            b"processor\t: 0\n"
            b"vendor_id\t: GenuineIntel\n"
            b"model name\t: Example CPU\n"
            b"cpu MHz\t\t: 3200.000\n"
            b"bogomips\t: 6400.00\n"
        )
        after = before.replace(b"3200.000", b"800.000").replace(b"6400.00", b"1600.00")
        different_cpu = after.replace(b"Example CPU", b"Different CPU")

        self.assertEqual(runner.cpuinfo_identity_sha256(before), runner.cpuinfo_identity_sha256(after))
        self.assertNotEqual(runner.cpuinfo_identity_sha256(before), runner.cpuinfo_identity_sha256(different_cpu))

    def test_pin_cpu_retains_the_pre_pin_controller_mask(self) -> None:
        """Peer selection must not rediscover the post-pin singleton mask."""

        with patch.object(runner.os, "sched_getaffinity", side_effect=({2, 7}, {2})), \
             patch.object(runner.os, "sched_setaffinity") as set_affinity:
            cpu, allowed = runner.pin_cpu(None)
        self.assertEqual((cpu, allowed), (2, (2, 7)))
        set_affinity.assert_called_once_with(0, {2})

    def test_peer_setup_receives_a_distinct_cpu_from_the_original_mask(self) -> None:
        """The measured client CPU cannot become the loopback/DNS peer CPU."""

        row = next(item for item in runner.performance_rows(ROOT) if item.name == "loopback_tcp_ipv4_4k")
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            root = Path(temporary)
            lane = runner.Lane(
                name="musl", root=root,
                binaries={row.timed_artifact: "/app/bin/x86_64_network_workload"},
                dsos={}, io_file=root / "io", span_inputs={}, environment={},
            )
            context = Mock()
            context.argv = tuple(runner.virtual_arguments(row, lane)[2:])
            with patch.object(runner.peers, "start_context", return_value=context) as started:
                actual = runner.start_row_peer(
                    ROOT, lane, row, root / "peer", client_cpu=2, peer_cpu=7,
                    allowed_affinity=(2, 7), timeout=1.0,
                )
        self.assertIs(actual, context)
        self.assertEqual(started.call_args.kwargs["cpu"], 7)
        self.assertEqual(started.call_args.kwargs["allowed_affinity"], (2, 7))
        context.stage_resolver_files.assert_called_once_with()


class MuslRuntimeStagingTests(unittest.TestCase):
    def test_stage_keeps_the_fixed_musl_interpreter_path(self) -> None:
        """The kernel follows the compiler-selected `/opt` PT_INTERP path."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            musl = directory / "musl"
            source_lib = musl / "lib"
            source_lib.mkdir(parents=True)
            (source_lib / "ld-musl-x86_64.so.1").write_bytes(b"loader")
            (source_lib / "libc.so").write_bytes(b"libc")
            root = directory / "root"
            root.mkdir()

            runner.stage_musl_runtime(root, musl)

            interpreter = root / runner.evidence.FIXED_MUSL_LOADER.lstrip("/")
            self.assertTrue(interpreter.is_symlink())
            self.assertEqual(os.readlink(interpreter), "../../../lib/ld-musl-x86_64.so.1")
            self.assertEqual(interpreter.resolve().read_bytes(), b"loader")
            self.assertEqual((root / "opt/musl-1.2.6/lib/libc.so").resolve().read_bytes(), b"libc")
            inventory = runner.evidence.inventory_tree(root)
            self.assertIn({
                "path": "opt/musl-1.2.6/lib/ld-musl-x86_64.so.1",
                "kind": "symlink",
                "target": "../../../lib/ld-musl-x86_64.so.1",
            }, inventory)

    def test_inventory_rejects_relative_alias_that_resolves_outside_root(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            root = directory / "root"
            root.mkdir()
            (directory / "outside").write_bytes(b"outside")
            (root / "escape").symlink_to("../outside")

            with self.assertRaisesRegex(runner.evidence.EvidenceError, "escapes its inventory"):
                runner.evidence.inventory_tree(root)


class PerformanceRowContractTests(unittest.TestCase):
    def test_closed_114_row_timing_and_memory_artifact_roster(self) -> None:
        """The observer envelope augments every frozen and supplemental row."""

        rows = runner.performance_rows(ROOT)
        by_name = {row.name: row for row in rows}

        self.assertEqual(len(rows), 114)
        self.assertEqual(len(by_name), 114)
        self.assertEqual(sum(row.legacy for row in rows), 74)
        self.assertEqual(sum(not row.legacy for row in rows), 40)

        startup = by_name["startup"]
        self.assertEqual(startup.timed_artifact, "workload")
        self.assertEqual(startup.memory_artifact, "x86_64_memory_observer_workload")
        self.assertEqual(startup.memory_phases, ("main-initial", "main-final"))

        tls = by_name["loader_dynamic_tls_growth"]
        self.assertEqual(
            tls.memory_phases,
            (
                "main-initial", *(f"tls-parent-load-{index}" for index in range(8)),
                "tls-worker-complete", "main-final",
            ),
        )

        allocator = by_name["allocator_live_32m"]
        self.assertFalse(allocator.legacy)
        self.assertEqual(allocator.timed_artifact, "x86_64_clock_allocator_workload")
        self.assertEqual(allocator.arguments, ("live", "1", "128", "262144"))
        self.assertEqual(allocator.iterations, 1)
        self.assertEqual(allocator.operations, 128)
        self.assertEqual(allocator.memory_artifact, "x86_64_memory_observer_clock_allocator")
        self.assertEqual(allocator.memory_phases, ("main-initial", "allocator-live", "main-final"))

        self.assertEqual(by_name["allocator_live_4m"].operations, 8192)
        self.assertEqual(by_name["allocator_refill_4m"].operations, 8192)
        self.assertEqual(by_name["allocator_worker_local_64"].operations, 16384)
        self.assertEqual(by_name["allocator_worker_local_4k"].operations, 16384)

        network = by_name["resolver_dns_tcp"]
        self.assertEqual(network.memory_artifact, "x86_64_memory_observer_network")
        self.assertEqual(network.memory_phases, ("main-initial", "resolver-final-result-live", "main-final"))
        self.assertTrue(network.requires_hermetic_resolver_files)

        primitive = by_name["memmem_guard63"]
        self.assertEqual(primitive.memory_artifact, "x86_64_memory_observer_primitive")
        self.assertEqual(primitive.memory_phases, ("main-initial", "primitive-guard-window-live", "main-final"))


class RosterBoundaryTests(unittest.TestCase):
    def test_unbound_smoke_does_not_claim_a_three_run_roster(self) -> None:
        args = type("Args", (), {"attempt_roster": None, "implementation_smoke": True})()
        self.assertEqual(runner.bind_attempt_roster(args, ROOT, WORK_ROOT, {}), {"status": "unbound"})

    def test_no_roster_non_smoke_rejects_before_environment_or_measurement(self) -> None:
        """Omitting a roster cannot turn an unavailable full run into a benchmark."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            args = SimpleNamespace(
                work_dir=Path(temporary) / "attempt",
                attempt_index=1,
                samples=None,
                warmup=None,
                implementation_smoke=False,
            )
            with patch.object(runner, "validate_environment", side_effect=AssertionError("environment reached")) as environment:
                _report_path, report = runner.run_attempt(args)
        self.assertFalse(environment.called)
        self.assertEqual(report["status"], "failed")
        self.assertIn("full native performance run is unavailable", report["failure"])

    def test_smoke_uses_fixed_reduced_process_budget(self) -> None:
        command = ["run", "--dynamic-product", "/product", "--work-dir", "/work"]
        normal = runner.parser().parse_args(command)
        runner.resolve_run_budget(normal)
        self.assertEqual((normal.samples, normal.warmup), (runner.DEFAULT_SAMPLES, runner.DEFAULT_WARMUP))

        smoke = runner.parser().parse_args([*command, "--implementation-smoke"])
        runner.resolve_run_budget(smoke)
        self.assertEqual((smoke.samples, smoke.warmup), (runner.SMOKE_SAMPLES, runner.SMOKE_WARMUP))

        oversized_smoke = runner.parser().parse_args([
            *command, "--implementation-smoke", "--samples", "31", "--warmup", "3",
        ])
        with self.assertRaisesRegex(runner.AdapterError, "fixed --samples"):
            runner.resolve_run_budget(oversized_smoke)

    def test_roster_rejects_an_invented_complete_correctness_status(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            product = {"manifest": {"sha256": "a" * 64}}
            requests = []
            for index in range(1, 4):
                work = directory / f"attempt-{index}"
                report = work / "report.json"
                requests.append({
                    "index": index,
                    "work_dir": runner.planned_recorded_path(ROOT, work),
                    "report": runner.planned_recorded_path(ROOT, report),
                    "predecessor_report": None if index == 1 else requests[index - 2]["report"],
                })
            roster = {
                "schema": runner.ROSTER_SCHEMA, "kind": runner.ROSTER_KIND, "status": "planned",
                "source_mount": runner.evidence.SOURCE_MOUNT, "source_revision": "b" * 40,
                "source_sha256": "c" * 64, "product": product,
                "dynamic_product_qualification": {
                    "status": "unavailable", "reason": "no validated owned-dynamic-qualification receipt was supplied",
                },
                "correctness_admission": {
                    "status": "complete", "required_owner": runner.COMPLETE_CORRECTNESS_OWNER,
                    "reason": "self-attested",
                },
                "attempts": requests,
            }
            roster_path = directory / "attempt-roster.json"
            runner.write_json(roster_path, roster)
            owner = SimpleNamespace(source_digest=lambda: "c" * 64)
            with patch.object(runner, "git_revision", return_value="b" * 40), \
                 patch.object(runner.evidence, "_x86_module", return_value=owner):
                with self.assertRaisesRegex(runner.AdapterError, "correctness admission"):
                    runner.load_attempt_roster(ROOT, roster_path, product)


if __name__ == "__main__":
    unittest.main()
