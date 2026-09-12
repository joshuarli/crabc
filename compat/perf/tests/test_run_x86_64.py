"""Focused lifecycle and retention tests for the native C-performance runner."""

from __future__ import annotations

import importlib.util
import os
import signal
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


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
