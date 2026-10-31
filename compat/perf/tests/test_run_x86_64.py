"""Focused lifecycle and retention tests for the native C-performance runner."""

from __future__ import annotations

import importlib.util
from contextlib import ExitStack
from typing import Any, Mapping, Sequence
import json
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


class MemoryObserverRawTotalsTests(unittest.TestCase):
    def test_producer_and_replay_preserve_unadjusted_pss_and_peak_totals(self) -> None:
        def provider(pss: int, peak: int) -> dict[str, object]:
            return {"status": "ok", "checkpoints": [{"memory": {"pss_kib": pss}}],
                    "cgroup_memory": {"memory_peak_after_exit_bytes": peak}}

        reference = provider(33 * 1024, 33 << 20)
        candidate = provider(33 * 1024, 33 << 20)
        comparison = runner.memory_observer_comparison(reference, candidate)
        self.assertEqual(comparison, {
            "status": "ok",
            "pss_max_kib": {"reference": 33 * 1024, "candidate": 33 * 1024},
            "memory_peak_after_exit_bytes": {"reference": 33 << 20, "candidate": 33 << 20},
        })
        runner.evidence._verify_memory_observer_comparison(comparison, reference, candidate, "allocator_live_32m")

        altered = {**comparison, "pss_max_kib": {"reference": 33 * 1024, "candidate": 33 * 1024 - 1}}
        with self.assertRaisesRegex(runner.evidence.EvidenceError, "raw checkpoints"):
            runner.evidence._verify_memory_observer_comparison(altered, reference, candidate, "allocator_live_32m")


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
    def test_supplemental_only_smoke_seals_the_live_memory_probe_binary(self) -> None:
        """The fixed live memory diagnostic needs its legacy workload executable."""

        selected = [row for row in runner.performance_rows(ROOT) if row.name == "allocator_live_4m"]
        sources, _headers = runner.source_roster(
            ROOT, SimpleNamespace(local_sources={}), selected, include_memory_observers=True,
        )
        self.assertIn("workload", sources)

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

        # The descriptor must sit above every kept one but below the soft
        # limit, which is only 1024 on a default host.
        high = os.sysconf("SC_OPEN_MAX") - 1
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read_fd)
                source = os.open("/dev/null", os.O_RDONLY)
                try:
                    inherited = os.dup2(source, high)
                finally:
                    if source != high:
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
    def test_governor_sysfs_capture_retains_policy_fields_and_detects_drift(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            work = Path(temporary)
            source = work / "sysfs" / "cpu2" / "cpufreq"
            source.mkdir(parents=True)
            (source / "scaling_governor").write_text("performance\n", encoding="utf-8")
            (source / "scaling_available_governors").write_text(
                "performance powersave\n", encoding="utf-8")
            (source / "scaling_cur_freq").write_text("2400000\n", encoding="utf-8")
            retained = work / "raw" / "host" / "governor-sysfs"
            first = runner.capture_governor_sysfs(ROOT, retained, 2, work / "sysfs")
            self.assertEqual(first["scaling_governor"], "performance")
            self.assertEqual(first["scaling_available_governors"], "performance powersave")
            self.assertEqual(set(first["raw_sysfs"]["files"]), set(runner.evidence.GOVERNOR_SYSFS_FIELDS))
            self.assertFalse((retained / "cpu2/cpufreq/scaling_cur_freq").exists())
            self.assertEqual(runner.capture_governor_sysfs(ROOT, retained, 2, work / "sysfs"), first)
            (source / "scaling_governor").write_text("powersave\n", encoding="utf-8")
            with self.assertRaisesRegex(runner.AdapterError, "governor sysfs changed"):
                runner.capture_governor_sysfs(ROOT, retained, 2, work / "sysfs")

    def test_governor_sysfs_capture_preserves_unavailable_fields(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            work = Path(temporary)
            missing = runner.capture_governor_sysfs(ROOT, work / "missing-raw", 2, work / "absent")
            self.assertEqual((missing["scaling_governor"], missing["scaling_available_governors"]),
                             (None, None))
            self.assertEqual(missing["raw_sysfs"]["files"], {})
            source = work / "sysfs" / "cpu2" / "cpufreq"
            source.mkdir(parents=True)
            (source / "scaling_governor").write_text("performance\n", encoding="utf-8")
            partial = runner.capture_governor_sysfs(ROOT, work / "partial-raw", 2, work / "sysfs")
            self.assertEqual(partial["scaling_governor"], "performance")
            self.assertIsNone(partial["scaling_available_governors"])
            self.assertEqual(set(partial["raw_sysfs"]["files"]), {"scaling_governor"})

    def test_cache_sysfs_capture_retains_selected_cpu_bytes_and_detects_drift(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            work = Path(temporary)
            source = work / "sysfs" / "cpu2" / "cache" / "index0"
            source.mkdir(parents=True)
            for name, value in {
                "level": "1\n", "coherency_line_size": "64\n", "type": "Data\n",
                "size": "32K\n", "shared_cpu_list": "2-3\n",
            }.items():
                (source / name).write_text(value, encoding="ascii")
            retained = work / "raw" / "host" / "cache-sysfs"
            first = runner.capture_cache_sysfs(ROOT, retained, 2, work / "sysfs")
            self.assertTrue(first["available"])
            self.assertEqual(set(first["files"]), {f"index0/{name}" for name in runner.aarch64_contract.CACHE_SYSFS_FIELDS})
            self.assertEqual((retained / "cpu2/cache/index0/size").read_bytes(), b"32K\n")
            self.assertEqual(runner.capture_cache_sysfs(ROOT, retained, 2, work / "sysfs"), first)
            (source / "size").write_text("512K\n", encoding="ascii")
            with self.assertRaisesRegex(runner.AdapterError, "cache sysfs changed"):
                runner.capture_cache_sysfs(ROOT, retained, 2, work / "sysfs")

    def test_cache_sysfs_capture_preserves_absent_and_instruction_only_inputs(self) -> None:
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            work = Path(temporary)
            missing = runner.capture_cache_sysfs(ROOT, work / "missing-raw", 2, work / "absent")
            self.assertEqual((missing["available"], missing["files"]), (False, {}))
            source = work / "sysfs" / "cpu2" / "cache" / "index0"
            source.mkdir(parents=True)
            for name, value in {
                "level": "1\n", "coherency_line_size": "64\n", "type": "Instruction\n",
                "size": "32K\n", "shared_cpu_list": "2\n",
            }.items():
                (source / name).write_text(value, encoding="ascii")
            retained = work / "instruction-raw"
            captured = runner.capture_cache_sysfs(ROOT, retained, 2, work / "sysfs")
            self.assertTrue(captured["available"])
            self.assertEqual(runner.aarch64_contract.benchmark_cpu_cache_topology(2, retained),
                             {"status": "unsupported", "reason": "no data or unified cache entries"})
            (source / "size").unlink()
            incomplete = runner.capture_cache_sysfs(ROOT, work / "incomplete-raw", 2, work / "sysfs")
            self.assertNotIn("index0/size", incomplete["files"])
            self.assertEqual(runner.aarch64_contract.benchmark_cpu_cache_topology(
                2, work / "incomplete-raw")["status"], "unsupported")

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


class StagedInputTests(unittest.TestCase):
    def test_staged_lane_arguments_match_the_replayed_file_contract(self) -> None:
        """The adapter's staged argv is the reader's canonical argv for file rows."""

        rows = {row.name: row for row in runner.performance_rows(ROOT)}
        lane = runner.Lane(
            name="musl", root=WORK_ROOT, binaries={"workload": "/app/bin/workload"}, dsos={},
            io_file=runner.evidence.IO_FIXTURE_FILE, span_inputs={}, environment={},
        )
        canonical = runner.evidence.canonical_workload_invocations(ROOT)
        for name in ("fd_file_4k", "stdio_file_4k", "stdio_format_parse"):
            with self.subTest(name):
                self.assertEqual(runner.virtual_arguments(rows[name], lane), canonical[name]["arguments"])


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

    def test_full_roster_run_waits_for_the_ordered_chain_before_environment(self) -> None:
        """A roster cannot admit a full run while any predecessor gate is open."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            args = SimpleNamespace(
                work_dir=Path(temporary) / "attempt",
                attempt_index=1,
                attempt_roster=Path(temporary) / "attempt-roster.json",
                samples=None,
                warmup=None,
                implementation_smoke=False,
            )
            with patch.object(runner, "validate_environment", side_effect=AssertionError("environment reached")) as environment:
                _report_path, report = runner.run_attempt(args)
        self.assertFalse(environment.called)
        self.assertEqual(report["status"], "failed")
        self.assertIn("capability.accounting: ready, no qualification execution receipt", report["failure"])

    def test_smoke_roster_binds_its_completed_smoke_predecessor(self) -> None:
        """A roster's predecessor is complete at the roster's own budget."""

        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary:
            directory = Path(temporary)
            requests = []
            for index in range(1, 4):
                work = directory / f"attempt-{index}"
                requests.append({
                    "index": index,
                    "work_dir": runner.planned_recorded_path(ROOT, work),
                    "report": runner.planned_recorded_path(ROOT, work / "report.json"),
                    "predecessor_report": None if index == 1 else requests[index - 2]["report"],
                })
            roster = {"budget": runner.evidence.SMOKE_BUDGET,
                      "correctness_admission": runner.evidence.correctness_admission(ROOT), "attempts": requests}
            (directory / "attempt-1").mkdir()
            (directory / "attempt-2").mkdir()
            prior = {"schema": runner.SCHEMA, "kind": runner.KIND, "attempt": {"index": 1}}
            args = SimpleNamespace(attempt_roster=directory / "attempt-roster.json", attempt_index=2,
                                   skip_syscalls=False, workload=None, implementation_smoke=True)
            with patch.object(runner, "load_attempt_roster", return_value=(args.attempt_roster, roster)), \
                 patch.object(runner, "recorded_identity", return_value={"path": "recorded"}):
                for status, accepted in ((runner.evidence.SMOKE_BUDGET, True), ("complete-evidence", False), ("partial-evidence", False)):
                    with self.subTest(status):
                        runner.write_json(directory / "attempt-1/report.json", {**prior, "status": status})
                        if accepted:
                            bound = runner.bind_attempt_roster(args, ROOT, directory / "attempt-2", {})
                            self.assertEqual(bound["predecessor"], {"path": "recorded"})
                        else:
                            with self.assertRaisesRegex(runner.AdapterError, "predecessor is incomplete"):
                                runner.bind_attempt_roster(args, ROOT, directory / "attempt-2", {})

    def test_roster_budget_and_complete_roster_bind_each_attempt(self) -> None:
        admission = runner.evidence.correctness_admission(ROOT)
        roster = {"budget": runner.evidence.SMOKE_BUDGET, "correctness_admission": admission,
                  "attempts": [{"index": 1, "work_dir": "unused", "report": "unused", "predecessor_report": None}]}
        path = WORK_ROOT / "attempt-roster.json"
        base = {"attempt_roster": path, "attempt_index": 1, "skip_syscalls": False, "workload": None}
        with patch.object(runner, "load_attempt_roster", return_value=(path, roster)), \
             patch.object(runner, "require_full_run_admission"):
            full = SimpleNamespace(**base, implementation_smoke=False)
            with self.assertRaisesRegex(runner.AdapterError, "differs from the immutable implementation-smoke roster"):
                runner.bind_attempt_roster(full, ROOT, WORK_ROOT, {})
            subset = SimpleNamespace(**{**base, "workload": ["startup"]}, implementation_smoke=True)
            with self.assertRaisesRegex(runner.AdapterError, "every canonical row"):
                runner.bind_attempt_roster(subset, ROOT, WORK_ROOT, {})
            untraced = SimpleNamespace(**{**base, "skip_syscalls": True}, implementation_smoke=True)
            with self.assertRaisesRegex(runner.AdapterError, "every canonical row"):
                runner.bind_attempt_roster(untraced, ROOT, WORK_ROOT, {})

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
                    "status": "available", "owner": runner.evidence.CORRECTNESS_OWNER, "unmet": [],
                },
                "budget": runner.evidence.FULL_BUDGET,
                "attempts": requests,
            }
            roster_path = directory / "attempt-roster.json"
            runner.write_json(roster_path, roster)
            owner = SimpleNamespace(source_digest=lambda: "c" * 64)
            real_module = runner.evidence._x86_module

            def module(checkout: Path, name: str) -> object:
                # Replace only the source-digest owner; admission still reads
                # the real ordered qualification chain.
                return owner if name == "owned_dynamic_qualification" else real_module(checkout, name)

            with patch.object(runner, "git_revision", return_value="b" * 40), \
                 patch.object(runner.evidence, "_x86_module", side_effect=module):
                with self.assertRaisesRegex(runner.AdapterError, "ordered qualification chain"):
                    runner.load_attempt_roster(ROOT, roster_path, product)


class MemoryCollectorSmokeTests(unittest.TestCase):
    def test_collector_captures_host_raw_paths_and_preserves_observations_and_cleanup(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "crabc_memory_collector_smoke", ROOT / "compat/perf/tests/run_x86_64_memory_collector_smoke.py")
        assert spec is not None and spec.loader is not None
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        selected = smoke.selected_rows()
        observations = {}
        leaves = []
        for row in selected:
            lanes = {}
            for lane in ("musl", "crabc"):
                leaf = f"{row.name}-{lane}"
                leaves.append(leaf)
                lanes[lane] = {
                    "status": "ok",
                    "migration": {"event": "syscall-entry-execve", "threads": 1,
                                  "syscall": {"entry": True}, "probe": leaf},
                    "checkpoints": [{"phase": phase, "ready": "R", "continue": "C",
                                     "memory": {"pss_kib": 1, "raw": {}}, "mappings": {"raw": {}}}
                                    for phase in row.memory_phases],
                    "cgroup_memory": {"status": "ok", "memory_peak_after_exit_bytes": 1, "raw": {}},
                    "peer": {"status": "complete", "row": {"id": row.name}}
                            if row.name == "loopback_tcp_ipv4_4k" else None,
                }
            observations[row.name] = {"invocation": {"phases": list(row.memory_phases)},
                                      **lanes, "comparison": {"status": "ok"}}
        cleanup = {"owned_leaves": leaves, "remaining_leaves": [], "unmount_status": 0}
        session = Mock()
        session.close.return_value = cleanup
        with tempfile.TemporaryDirectory(dir=WORK_ROOT) as temporary, ExitStack() as stack:
            directory = Path(temporary)
            work = directory / "collector"
            args = SimpleNamespace(work=work, dynamic_product=directory / "product", cpu=2, timeout=1.0)
            owner = smoke.runner
            for name, value in {
                "git_clean": True, "git_revision": "a" * 40,
                "validate_environment": (args.dynamic_product, directory / "musl", directory / "musl-cc",
                                         2, (2, 3), 3),
                "make_generated_sources": None, "source_roster": ({}, {}),
                "compile_required_objects": None, "link_required_artifacts": None,
                "stage_lane": None, "record_product": {"root": "mock-product"},
            }.items():
                stack.enter_context(patch.object(owner, name, return_value=value))
            stack.enter_context(patch.object(owner.CgroupSession, "create", return_value=session))
            collect = stack.enter_context(patch.object(owner, "collect_memory_observers", return_value=observations))
            host = stack.enter_context(patch.object(owner, "host_snapshot", autospec=True,
                                                   return_value={"captured": "mock-host"}))
            report = smoke.run(args)
            host.assert_called_once_with(ROOT, work / "raw/host/cache-sysfs", work / "raw/host/governor-sysfs",
                                         2, (2, 3), 3)
            self.assertEqual(collect.call_args.args[4], work / "raw/execution")
            session.close.assert_called_once_with()
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(result["schema"], "crabc.perf.x86_64-memory-collector-smoke/v1")
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["rows"], list(smoke.SMOKE_ROWS))
            self.assertEqual(result["host"], {"captured": "mock-host"})
            self.assertEqual(result["observations"], observations)
            self.assertEqual(result["cleanup"], cleanup)


class CountsPureHelpersTests(unittest.TestCase):
    def test_per_op_arithmetic_is_a_plain_difference_quotient(self) -> None:
        self.assertAlmostEqual(runner.counts_per_op(3_000_000, 1_000_000, 400_000, 200_000), 10.0)
        self.assertAlmostEqual(runner.counts_per_op(50, 30, 3, 1), 10.0)

    def test_wrapper_subtraction_is_exact(self) -> None:
        self.assertEqual(runner.counts_subtract(36_170, 2_000), 34_170)

    def test_cost_contract_constants_come_from_evidence_without_copies(self) -> None:
        self.assertEqual(runner.evidence.SYSCALL_LIMIT_FACTOR, 1)
        self.assertEqual(runner.evidence.INSTRUCTION_LIMIT_RATIO, 1.10)
        self.assertFalse(hasattr(runner, "SYSCALL_LIMIT_FACTOR"))
        self.assertFalse(hasattr(runner, "INSTRUCTION_LIMIT_RATIO"))

    def test_three_runs_agree_within_point_zero_one_percent(self) -> None:
        self.assertTrue(runner.counts_runs_agree([1_000_000, 1_000_050, 999_950]))
        self.assertFalse(runner.counts_runs_agree([1_000_000, 1_000_000, 1_000_201]))
        self.assertTrue(runner.counts_runs_agree([0, 0, 0]))
        self.assertFalse(runner.counts_runs_agree([0, 0, 1]))

    def test_linearity_requires_half_percent_step_agreement(self) -> None:
        self.assertTrue(runner.counts_linear(1_000_000, 2_000_000, 3_000_000))
        self.assertFalse(runner.counts_linear(1_000_000, 2_000_000, 3_020_000))
        self.assertTrue(runner.counts_linear(5, 5, 5))
        self.assertFalse(runner.counts_linear(5, 5, 6))

    def test_n1_scales_the_reference_loop_to_one_million_instructions(self) -> None:
        self.assertEqual(runner.scale_counts_n1(200_000, 10_000_000, 2_000), 200_000)
        self.assertEqual(runner.scale_counts_n1(1_000, 500_000, 0), 2_000)
        with self.assertRaisesRegex(runner.AdapterError, "not positive"):
            runner.scale_counts_n1(1_000, 0, 0)

    def test_reference_selection_prefers_matched_llvm_major(self) -> None:
        matched, label = runner.select_counts_reference(
            {"/opt/musl-clang-1.2.6": "Alpine clang version 23.1.4\n"}, "LLVM version: 23.1.1\n")
        self.assertEqual((matched, label), ("/opt/musl-clang-1.2.6", "matched-llvm-23"))
        fallback, fallback_label = runner.select_counts_reference(
            {"/opt/musl-clang-1.2.6": "Alpine clang version 22.1.3\n"}, "LLVM version: 23.1.1\n")
        self.assertEqual((fallback, fallback_label), (str(runner.DEFAULT_MUSL_ROOT), "unmatched (gcc musl)"))
        missing, missing_label = runner.select_counts_reference({}, "LLVM version: 23.1.1\n")
        self.assertEqual((missing, missing_label), (str(runner.DEFAULT_MUSL_ROOT), "unmatched (gcc musl)"))
        with self.assertRaisesRegex(runner.AdapterError, "LLVM version"):
            runner.select_counts_reference({}, "no version here\n")

    def test_perf_stat_csv_parses_one_count_per_repeat(self) -> None:
        text = ("1234567,,instructions:u,1000000,100.00,,,\n"
                "1234580,,instructions:u,1001000,100.00,,,\n"
                "1234550,,instructions:u,999000,100.00,,,\n")
        self.assertEqual(runner.parse_perf_counts(text), [1234567, 1234580, 1234550])
        self.assertEqual(runner.parse_perf_counts("garbage\n"), [])

    def test_strace_parse_counts_calls_after_the_client_execve(self) -> None:
        text = ("100 execve(\"/app/bin/other\", [\"x\"], 0x1) = 0\n"
                "100 execve(\"/app/bin/workload\", [\"/app/bin/workload\", \"getpid\", \"3\"], 0x1) = 0\n"
                "100 getpid() = 42\n"
                "100 getpid() = 43\n"
                "100 +++ exited with 0 +++\n")
        parsed = runner.parse_strace_whole(text, "/app/bin/workload")
        self.assertEqual(parsed["total"], 3)
        self.assertEqual(parsed["calls"], {"execve": 1, "getpid": 2})
        self.assertEqual([(entry.name, entry.arguments) for entry in parsed["entries"]],
                         [("execve", '"/app/bin/workload", ["/app/bin/workload", "getpid", "3"], 0x1'),
                          ("getpid", ""), ("getpid", "")])
        with self.assertRaisesRegex(runner.AdapterError, "no client execve"):
            runner.parse_strace_whole("100 getpid() = 1\n", "/app/bin/workload")

    def test_strace_arguments_stop_at_the_syscall_close(self) -> None:
        text = ("200 execve(\"/app/bin/workload\", [\"/app/bin/workload\", \"startup\", \"1\"], 0x1) = 0\n"
                "200 open(\"/proc/sys/vm/overcommit_memory\", O_RDONLY) = -1 ENOENT "
                "(No such file or directory)\n"
                "200 mmap(NULL, 2359296, PROT_READ|PROT_WRITE, "
                "MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0) = 0x7f00\n")
        parsed = runner.parse_strace_whole(text, "/app/bin/workload")
        self.assertEqual(parsed["entries"][1].arguments, '"/proc/sys/vm/overcommit_memory", O_RDONLY')
        self.assertEqual(runner.allocator_startup_signature(parsed["entries"][1]),
                         'open("/proc/sys/vm/overcommit_memory")')
        self.assertEqual(runner.allocator_startup_signature(parsed["entries"][2]),
                         "mmap(2359296, MAP_NORESERVE)")

    def test_client_only_startup_trace_excludes_the_launcher_parent(self) -> None:
        text = ("144 poll([{fd=4, events=POLLIN}], 1, 20000) = 1\n"
                "145 execve(\"/app/bin/workload\", [\"/app/bin/workload\", \"startup\", \"1\"], 0x1) = 0\n"
                "145 arch_prctl(ARCH_SET_FS, 0x1) = 0\n"
                "144 poll([{fd=4, events=POLLIN}], 1, 20000) = 1\n"
                "145 exit_group(0) = ?\n"
                "144 wait4(145, [{WIFEXITED(s)}], 0, {}) = 145\n")
        whole = runner.parse_strace_whole(text, "/app/bin/workload")
        client = runner.parse_strace_whole(text, "/app/bin/workload", client_only=True)
        self.assertEqual(whole["calls"], {"execve": 1, "arch_prctl": 1, "poll": 1, "exit_group": 1, "wait4": 1})
        self.assertEqual(client["calls"], {"execve": 1, "arch_prctl": 1, "exit_group": 1})
        self.assertEqual(client["total"], 3)

    def allocator_calls(self) -> list[runner.TracedCall]:
        return [
            runner.TracedCall("sysinfo", "{uptime=1, loads=[1, 2, 3]}"),
            runner.TracedCall("open", '"/proc/sys/vm/overcommit_memory", O_RDONLY'),
            runner.TracedCall("open", '"/sys/kernel/mm/transparent_hugepage/enabled", O_RDONLY'),
            runner.TracedCall(
                "mmap", "NULL, 2359296, PROT_READ|PROT_WRITE, "
                        "MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0"),
            runner.TracedCall("getrandom", '"\\x01\\x02", 32, GRND_NONBLOCK'),
        ]

    def startup_reference(self) -> dict[str, int]:
        return {"execve": 1, "arch_prctl": 1, "set_tid_address": 1, "brk": 2,
                "mmap": 1, "mprotect": 2, "exit_group": 1}

    def startup_others(self) -> list[runner.TracedCall]:
        return [
            runner.TracedCall("execve", '"/app/bin/workload", ["/app/bin/workload", "startup", "1"], 0x1'),
            runner.TracedCall("arch_prctl", "ARCH_SET_FS, 0x7f00"),
            runner.TracedCall("set_tid_address", "0x7f01"),
            runner.TracedCall("mmap", "0x7f02, 4096, PROT_READ, MAP_PRIVATE|MAP_FIXED, 3, 0"),
            runner.TracedCall("mprotect", "0x7f03, 4096, PROT_READ"),
            runner.TracedCall("mprotect", "0x7f04, 4096, PROT_READ"),
            runner.TracedCall("exit_group", "0"),
        ]

    def startup_status(self, candidate: Sequence[runner.TracedCall], reference: Mapping[str, int],
                       ratio_insn: float = 1.0) -> tuple[str, dict[str, Any]]:
        judgement = runner.judge_allocator_syscalls(reference, candidate)
        status = runner.classify_counts_row(
            has_counts=True, deterministic=True, linear=True, matched=True,
            ref_sys_perop=judgement["reference"]["total"], cand_sys_perop=judgement["judged"]["total"],
            ref_sys_whole=judgement["reference"]["total"], cand_sys_whole=judgement["judged"]["total"],
            ratio_insn=ratio_insn, syscall_excess=judgement["excess"])
        return status, judgement

    def test_startup_classifies_exactly_the_five_allocator_calls_by_arguments(self) -> None:
        signatures = [runner.allocator_startup_signature(call) for call in self.allocator_calls()]
        self.assertEqual(signatures, [
            "sysinfo",
            'open("/proc/sys/vm/overcommit_memory")',
            'open("/sys/kernel/mm/transparent_hugepage/enabled")',
            "mmap(2359296, MAP_NORESERVE)",
            "getrandom(32, GRND_NONBLOCK)",
        ])
        self.assertEqual(set(signatures), set(runner.ALLOCATOR_STARTUP_SIGNATURES))
        self.assertIsNone(runner.allocator_startup_signature(
            runner.TracedCall("getrandom", '"\\x01", 64, GRND_NONBLOCK')))
        self.assertIsNone(runner.allocator_startup_signature(
            runner.TracedCall("mmap", "NULL, 2359296, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0")))
        self.assertIsNone(runner.allocator_startup_signature(
            runner.TracedCall("open", '"/proc/sys/vm/overcommit_memory.bak", O_RDONLY')))
        self.assertIsNone(runner.allocator_startup_signature(
            runner.TracedCall("openat", 'AT_FDCWD, "/proc/sys/vm/overcommit_memory", O_RDONLY')))
        self.assertIsNone(runner.allocator_startup_signature(runner.TracedCall("gettid", "")))

    def test_startup_judges_only_the_remaining_calls_against_the_reference(self) -> None:
        status, judgement = self.startup_status(self.allocator_calls() + self.startup_others(),
                                                self.startup_reference())
        self.assertEqual(judgement["allocator_attributed"]["total"], 5)
        self.assertEqual(judgement["allocator_attributed"]["signatures"],
                         list(runner.ALLOCATOR_STARTUP_SIGNATURES))
        self.assertEqual(judgement["judged"]["total"], 7)
        self.assertEqual(judgement["reference"]["total"], 9)
        self.assertEqual(judgement["excess"], {})
        self.assertEqual(status, "pass")
        kinds = list((call.name, call.arguments) for call in self.allocator_calls())
        self.assertEqual(len(kinds), 5)

    def test_startup_fails_on_a_sixth_non_allocator_call(self) -> None:
        status, judgement = self.startup_status(
            self.allocator_calls() + self.startup_others() + [runner.TracedCall("gettid", "")],
            self.startup_reference())
        self.assertEqual(judgement["judged"]["total"], 8)
        self.assertEqual(judgement["excess"], {"gettid": 1})
        self.assertEqual(status, "fail")

    def test_startup_fails_on_an_allocator_call_with_an_unexpected_argument(self) -> None:
        calls = self.allocator_calls()
        calls[-1] = runner.TracedCall("getrandom", '"\\x01", 64, GRND_NONBLOCK')
        status, judgement = self.startup_status(calls + self.startup_others(), self.startup_reference())
        self.assertEqual(judgement["allocator_attributed"]["total"], 4)
        self.assertEqual(judgement["excess"], {"getrandom": 1})
        self.assertEqual(status, "fail")
        missing_mmap = self.allocator_calls()
        missing_mmap[3] = runner.TracedCall(
            "mmap", "NULL, 2359296, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0")
        status, judgement = self.startup_status(missing_mmap + self.startup_others(),
                                                self.startup_reference())
        self.assertEqual(judgement["allocator_attributed"]["total"], 4)
        self.assertEqual(judgement["excess"], {"mmap": 1})
        self.assertEqual(status, "fail")

    def test_startup_instruction_ratio_still_judges_the_total(self) -> None:
        status, _judgement = self.startup_status(self.allocator_calls() + self.startup_others(),
                                                 self.startup_reference(), ratio_insn=1.1001)
        self.assertEqual(status, "fail")
        status, _judgement = self.startup_status(self.allocator_calls() + self.startup_others(),
                                                 self.startup_reference(), ratio_insn=1.10)
        self.assertEqual(status, "pass")

    def loop_reference(self) -> dict[str, int]:
        return {"execve": 1, "arch_prctl": 1, "set_tid_address": 1, "brk": 2,
                "mmap": 1, "mprotect": 2, "ioctl": 1, "writev": 1, "exit_group": 1,
                "getpid": 1000}

    def loop_others(self) -> list[runner.TracedCall]:
        return [
            runner.TracedCall("execve", '"/app/bin/workload", ["/app/bin/workload", "getpid", "1000"], 0x1'),
            runner.TracedCall("arch_prctl", "ARCH_SET_FS, 0x7f00"),
            runner.TracedCall("set_tid_address", "0x7f01"),
            runner.TracedCall("mmap", "0x7f02, 4096, PROT_READ, MAP_PRIVATE|MAP_FIXED, 3, 0"),
            runner.TracedCall("mprotect", "0x7f03, 4096, PROT_READ"),
            runner.TracedCall("mprotect", "0x7f04, 4096, PROT_READ"),
            runner.TracedCall("ioctl", "1, TIOCGWINSZ, 0x7fff"),
            runner.TracedCall("writev", '1, [{iov_base="ok", iov_len=2}], 1'),
            runner.TracedCall("exit_group", "0"),
        ] + [runner.TracedCall("getpid", "")] * 1000

    def loop_status(self, candidate: Sequence[runner.TracedCall], reference: Mapping[str, int],
                    *, ref_perop: float = 1.0, cand_perop: float = 1.0,
                    ratio_insn: float = 1.0) -> tuple[str, dict[str, Any]]:
        judgement = runner.judge_allocator_syscalls(reference, candidate)
        status = runner.classify_counts_row(
            has_counts=True, deterministic=True, linear=True, matched=True,
            ref_sys_perop=ref_perop, cand_sys_perop=cand_perop,
            ref_sys_whole=judgement["reference"]["total"],
            cand_sys_whole=judgement["judged"]["total"],
            ratio_insn=ratio_insn, syscall_excess=judgement["excess"])
        return status, judgement

    def test_loop_row_subtracts_the_five_allocator_calls_from_its_whole_count(self) -> None:
        status, judgement = self.loop_status(self.allocator_calls() + self.loop_others(),
                                             self.loop_reference())
        self.assertEqual(judgement["allocator_attributed"]["total"], 5)
        self.assertEqual(judgement["allocator_attributed"]["signatures"],
                         list(runner.ALLOCATOR_STARTUP_SIGNATURES))
        self.assertEqual(judgement["judged"]["total"], 1009)
        self.assertEqual(judgement["reference"]["total"], 1011)
        self.assertEqual(judgement["excess"], {})
        self.assertEqual(status, "pass")

    def test_loop_row_fails_on_a_sixth_non_allocator_startup_call(self) -> None:
        status, judgement = self.loop_status(
            self.allocator_calls() + self.loop_others() + [runner.TracedCall("gettid", "")],
            self.loop_reference())
        self.assertEqual(judgement["excess"], {"gettid": 1})
        self.assertEqual(status, "fail")

    def test_loop_row_does_not_exempt_an_allocator_call_outside_the_signature(self) -> None:
        cases = [
            (1, runner.TracedCall("open", '"/proc/sys/vm/overcommit_memory.bak", O_RDONLY')),
            (1, runner.TracedCall("openat", 'AT_FDCWD, "/proc/sys/vm/overcommit_memory", O_RDONLY')),
            (3, runner.TracedCall(
                "mmap", "NULL, 2359296, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0")),
            (3, runner.TracedCall(
                "mmap", "NULL, 4096, PROT_READ|PROT_WRITE, "
                        "MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0")),
            (4, runner.TracedCall("getrandom", '"\\x01", 31, GRND_NONBLOCK')),
            (4, runner.TracedCall("getrandom", '"\\x01", 32, GRND_RANDOM')),
        ]
        for index, replacement in cases:
            self.assertIsNone(runner.allocator_startup_signature(replacement))
            calls = list(self.allocator_calls())
            calls[index] = replacement
            status, judgement = self.loop_status(calls + self.loop_others(), self.loop_reference())
            self.assertEqual(judgement["allocator_attributed"]["total"], 4)
            self.assertNotEqual(judgement["excess"], {})
            self.assertEqual(status, "fail")

    def test_loop_row_still_fails_an_extra_per_op_call(self) -> None:
        status, judgement = self.loop_status(self.allocator_calls() + self.loop_others(),
                                             self.loop_reference(), ref_perop=3.0, cand_perop=4.0)
        self.assertEqual(judgement["excess"], {})
        self.assertEqual(status, "fail")
        status, judgement = self.loop_status(
            self.allocator_calls() + self.loop_others() + [runner.TracedCall("getpid", "")],
            self.loop_reference())
        self.assertEqual(judgement["excess"], {"getpid": 1})
        self.assertEqual(status, "fail")

    def base_kwargs(self, **changes: object) -> dict[str, object]:
        kwargs: dict[str, object] = {
            "has_counts": True, "deterministic": True, "linear": True, "matched": True,
            "ref_sys_perop": 1, "cand_sys_perop": 1,
            "ref_sys_whole": 40, "cand_sys_whole": 40, "ratio_insn": 1.0,
        }
        kwargs.update(changes)
        return kwargs

    def test_status_pass_and_every_failure_shape(self) -> None:
        self.assertEqual(runner.classify_counts_row(**self.base_kwargs()), "pass")
        self.assertEqual(runner.classify_counts_row(**self.base_kwargs(has_counts=False)), "unavailable")
        self.assertEqual(runner.classify_counts_row(**self.base_kwargs(ratio_insn=None)), "unavailable")
        self.assertEqual(runner.classify_counts_row(**self.base_kwargs(deterministic=False)), "nondeterministic")
        self.assertEqual(runner.classify_counts_row(**self.base_kwargs(linear=False)), "nonlinear")
        self.assertEqual(runner.classify_counts_row(**self.base_kwargs(matched=False)), "fail")
        self.assertEqual(runner.classify_counts_row(**self.base_kwargs(cand_sys_perop=2)), "fail")
        self.assertEqual(runner.classify_counts_row(**self.base_kwargs(cand_sys_whole=41)), "fail")
        self.assertEqual(runner.classify_counts_row(**self.base_kwargs(ratio_insn=1.1001)), "fail")
        self.assertEqual(runner.classify_counts_row(**self.base_kwargs(ratio_insn=1.10)), "pass")
        self.assertEqual(runner.classify_counts_row(**self.base_kwargs(
            ref_sys_perop=0, cand_sys_perop=1)), "fail")
        self.assertEqual(runner.classify_counts_row(**self.base_kwargs(allocator_attributed=True)), "allocator-attributed")


if __name__ == "__main__":
    unittest.main()
