#!/usr/bin/env python3
"""Behavioral contracts for the isolated Python unittest runner."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/test_python.py"
RUNS_ROOT = ROOT / ".work/python-test-runs"
RUN_ROOT_REPORT = re.compile(r"(?:logs:|retained logs:)\s+(\.work/python-test-runs/run-[^/\s;]+)")
SPEC = importlib.util.spec_from_file_location("crabc_test_python", RUNNER)
assert SPEC is not None and SPEC.loader is not None
RUNNER_MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER_MODULE
SPEC.loader.exec_module(RUNNER_MODULE)


class PythonTestRunnerTests(unittest.TestCase):
    """Exercise runner behavior through its public process boundary."""

    def setUp(self) -> None:
        scratch_root = ROOT / ".work/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        self.fixture_root = Path(tempfile.mkdtemp(prefix="test-python-runner-", dir=scratch_root))
        self.addCleanup(shutil.rmtree, self.fixture_root, ignore_errors=True)
        self.run_roots: list[Path] = []
        self.addCleanup(self.remove_run_roots)

    def remove_run_roots(self) -> None:
        for path in self.run_roots:
            self.remove_owned_run_root(path)

    def remove_owned_run_root(self, path: Path) -> None:
        try:
            resolved = path.resolve(strict=True)
        except FileNotFoundError:
            return
        if resolved == path and resolved.is_relative_to(RUNS_ROOT.resolve()) and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)

    def relative(self, path: Path) -> str:
        return path.relative_to(ROOT).as_posix()

    def report_run_root(self, result: subprocess.CompletedProcess[str]) -> Path | None:
        reported = set(RUN_ROOT_REPORT.findall(result.stdout + result.stderr))
        if not reported:
            return None
        self.assertEqual(len(reported), 1, result.stdout + result.stderr)
        path = ROOT / reported.pop()
        self.assertFalse(path.is_symlink())
        resolved = path.resolve(strict=True)
        self.assertEqual(resolved, path)
        self.assertTrue(resolved.is_relative_to(RUNS_ROOT.resolve()))
        return resolved

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [sys.executable, str(RUNNER), *arguments],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        run_root = self.report_run_root(result)
        if run_root is not None:
            self.run_roots.append(run_root)
        return result

    def write_module(self, name: str, body: str) -> Path:
        module = self.fixture_root / name
        module.write_text(body, encoding="utf-8")
        return module

    def only_run_root(self) -> Path:
        self.assertEqual(len(self.run_roots), 1)
        return self.run_roots[0]

    def assert_stopped(self, pid: int, message: str) -> None:
        state_path = Path(f"/proc/{pid}/stat")
        for _ in range(40):
            if not state_path.exists() or state_path.read_text(encoding="utf-8").split()[2] == "Z":
                return
            time.sleep(0.05)
        self.fail(message)

    def test_directory_workers_overlap_and_receive_private_checkout_roots(self) -> None:
        suite = self.fixture_root / "parallel"
        suite.mkdir()
        body = """\
import os
import time
import unittest
from pathlib import Path

class EnvironmentTests(unittest.TestCase):
    def test_private_worker_environment(self):
        run_root = Path(os.environ["CRABC_PYTHON_TEST_RUN_ROOT"])
        work_root = Path(os.environ["CRABC_PYTHON_TEST_WORK_ROOT"])
        temporary = Path(os.environ["TMPDIR"])
        scratch = Path(os.environ["CRABC_PYTHON_TEST_SCRATCH"])
        reports = Path(os.environ["CRABC_PYTHON_TEST_REPORTS"])
        self.assertTrue(all(path.is_relative_to(run_root) for path in (work_root, temporary, scratch, reports)))
        self.assertEqual(temporary.parent, work_root)
        self.assertEqual(scratch.parent, work_root)
        self.assertEqual(reports.parent, work_root)
        self.assertEqual(Path(os.environ["CRABC_WORK_DIR"]), work_root)
        coordinate = run_root / "coordination"
        coordinate.mkdir(exist_ok=True)
        name = Path(__file__).stem
        (coordinate / (name + ".ready")).write_text("ready", encoding="utf-8")
        deadline = time.monotonic() + 3
        while len(list(coordinate.glob("*.ready"))) < 2:
            if time.monotonic() >= deadline:
                self.fail("two-worker rendezvous timed out")
            time.sleep(0.01)
        (coordinate / (name + ".passed")).write_text("passed", encoding="utf-8")
        print("synthetic child output must stay in the captured log")
"""
        (suite / "test_one.py").write_text(body, encoding="utf-8")
        (suite / "test_two.py").write_text(body, encoding="utf-8")

        result = self.invoke("--directory", self.relative(suite), "--jobs", "2")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("passed 2 modules / 2 tests", result.stdout)
        self.assertNotIn("synthetic child output", result.stdout)
        run_root = self.only_run_root()
        self.assertEqual(len(list((run_root / "coordination").glob("*.passed"))), 2)
        summary = json.loads((run_root / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["jobs"], 2)
        self.assertEqual(summary["tests_run"], 2)
        self.assertEqual([row["module"] for row in summary["modules"]], [
            self.relative(suite / "test_one.py"), self.relative(suite / "test_two.py")
        ])
        for row in summary["modules"]:
            self.assertEqual(row["status"], "passed")
            self.assertEqual(row["tests_run"], 1)
            self.assertEqual(row["exit_code"], 0)
            self.assertGreaterEqual(row["elapsed_seconds"], 0)
            self.assertLessEqual(row["elapsed_seconds"], summary["elapsed_seconds"])
        for index, name in ((1, "test-one"), (2, "test-two")):
            worker = run_root / "modules" / f"{index:03d}-{name}"
            self.assertTrue((worker / "tmp").is_dir())
            self.assertTrue((worker / "scratch").is_dir())
            self.assertTrue((worker / "reports").is_dir())
            self.assertIn("synthetic child output", (worker / "stdout.log").read_text(encoding="utf-8"))

    def test_module_selection_and_zero_test_modules_fail_closed(self) -> None:
        module = self.write_module(
            "test_selected.py",
            """\
import unittest

class SelectedTests(unittest.TestCase):
    def test_selected(self):
        self.assertTrue(True)
""",
        )
        selected = self.invoke("--module", self.relative(module), "--module", self.relative(module), "--jobs", "1")
        self.assertEqual(selected.returncode, 0, selected.stdout + selected.stderr)
        self.assertIn("passed 1 modules / 1 tests", selected.stdout)

        empty = self.write_module("test_empty.py", "VALUE = 1\n")
        zero = self.invoke("--module", self.relative(empty), "--jobs", "1")
        self.assertEqual(zero.returncode, 1, zero.stdout + zero.stderr)
        self.assertIn("ZERO-TESTS", zero.stdout)

    def test_selected_cases_run_in_private_bounded_shards(self) -> None:
        module = self.write_module(
            "test_sharded.py",
            """\
import unittest

class ShardedTests(unittest.TestCase):
    def test_a(self): self.assertTrue(True)
    def test_b(self): self.assertTrue(True)
    def test_c(self): self.assertTrue(True)
    def test_d(self): self.assertTrue(True)
    def test_e(self): self.assertTrue(True)
""",
        )
        case_ids = [f"test_sharded.ShardedTests.test_{name}" for name in "abcde"]
        result = self.invoke(
            "--module",
            self.relative(module),
            *(argument for case_id in case_ids for argument in ("--case", case_id)),
            "--case-shard-size",
            "2",
            "--jobs",
            "2",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("passed 3 jobs / 5 tests", result.stdout)
        summary = json.loads((self.only_run_root() / "summary.json").read_text())
        self.assertEqual(summary["jobs"], 2)
        self.assertEqual(summary["tests_run"], 5)
        self.assertEqual(summary["tests_completed"], 5)
        self.assertEqual(
            [row["selected_case_ids"] for row in summary["modules"]],
            [case_ids[:2], case_ids[2:4], case_ids[4:]],
        )
        for index, row in enumerate(summary["modules"], start=1):
            self.assertEqual(row["status"], "passed")
            self.assertEqual(row["tests_run"], len(row["selected_case_ids"]))
            self.assertEqual(row["tests_completed"], len(row["selected_case_ids"]))
            self.assertIsNone(row["current_test_id"])
            worker = self.only_run_root() / "modules" / f"{index:03d}-test-sharded"
            progress = [
                line
                for line in (worker / "stdout.log").read_text().splitlines()
                if line.startswith(RUNNER_MODULE.PROGRESS_PREFIX)
            ]
            self.assertGreaterEqual(len(progress), 1 + 2 * len(row["selected_case_ids"]))

    def test_selected_shard_that_stops_early_fails_closed(self) -> None:
        module = self.write_module(
            "test_stopped_selection.py",
            """\\
import unittest

class StoppedSelectionTests(unittest.TestCase):
    def test_a_stops_the_result(self):
        self._outcome.result.stop()

    def test_b_must_not_be_silently_skipped(self):
        self.fail("the result stop should prevent this test from running")
""",
        )
        case_ids = [
            "test_stopped_selection.StoppedSelectionTests.test_a_stops_the_result",
            "test_stopped_selection.StoppedSelectionTests.test_b_must_not_be_silently_skipped",
        ]

        result = self.invoke(
            "--module",
            self.relative(module),
            *(argument for case_id in case_ids for argument in ("--case", case_id)),
            "--jobs",
            "1",
        )

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("INCOMPLETE-SELECTION", result.stdout)
        summary = json.loads((self.only_run_root() / "summary.json").read_text())
        self.assertEqual(summary["tests_run"], 1)
        self.assertEqual(summary["tests_completed"], 1)
        row = summary["modules"][0]
        self.assertEqual(row["selected_case_ids"], case_ids)
        self.assertEqual(row["status"], "incomplete-selection")
        records = [
            line
            for line in (self.only_run_root() / "modules/001-test-stopped-selection/stdout.log")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.startswith(RUNNER_MODULE.RESULT_PREFIX)
        ]
        self.assertEqual(len(records), 1)
        payload = json.loads(records[0][len(RUNNER_MODULE.RESULT_PREFIX):])
        self.assertEqual(payload["completed_case_ids"], case_ids[:1])

    def test_parity_ledger_shards_its_discovered_ids_without_running_them(self) -> None:
        arguments = RUNNER_MODULE.parse_args(
            [
                "--module",
                RUNNER_MODULE.PARITY_LEDGER_TEST_MODULE,
                "--case-shard-size",
                str(RUNNER_MODULE.DEFAULT_CASE_SHARD_SIZE),
                "--jobs",
                "4",
            ]
        )
        discovered = RUNNER_MODULE.parity_ledger_case_ids(
            ROOT / RUNNER_MODULE.PARITY_LEDGER_TEST_MODULE
        )
        jobs = RUNNER_MODULE.select_jobs(arguments)

        self.assertGreater(len(discovered), 300)
        self.assertEqual(
            tuple(case_id for job in jobs for case_id in job.case_ids), discovered
        )
        self.assertTrue(
            all(0 < len(job.case_ids) <= RUNNER_MODULE.DEFAULT_CASE_SHARD_SIZE for job in jobs)
        )

    def test_parity_ledger_auto_shards_among_multiple_selected_modules(self) -> None:
        arguments = RUNNER_MODULE.parse_args(
            [
                "--module",
                RUNNER_MODULE.PARITY_LEDGER_TEST_MODULE,
                "--module",
                "scripts/tests/test_test_python.py",
                "--jobs",
                "4",
            ]
        )
        discovered = RUNNER_MODULE.parity_ledger_case_ids(
            ROOT / RUNNER_MODULE.PARITY_LEDGER_TEST_MODULE
        )
        jobs = RUNNER_MODULE.select_jobs(arguments)

        parity_jobs = [job for job in jobs if job.module == ROOT / RUNNER_MODULE.PARITY_LEDGER_TEST_MODULE]
        ordinary_jobs = [job for job in jobs if job.module != ROOT / RUNNER_MODULE.PARITY_LEDGER_TEST_MODULE]
        self.assertEqual(tuple(case_id for job in parity_jobs for case_id in job.case_ids), discovered)
        self.assertTrue(
            all(0 < len(job.case_ids) <= RUNNER_MODULE.DEFAULT_CASE_SHARD_SIZE for job in parity_jobs)
        )
        self.assertEqual(ordinary_jobs, [RUNNER_MODULE.TestJob(ROOT / "scripts/tests/test_test_python.py")])

    def test_parity_ledger_auto_shards_from_directory_selection(self) -> None:
        arguments = RUNNER_MODULE.parse_args(
            [
                "--directory",
                "compat/x86_64/tests",
                "--pattern",
                "test_parity_ledger.py",
                "--jobs",
                "4",
            ]
        )
        discovered = RUNNER_MODULE.parity_ledger_case_ids(
            ROOT / RUNNER_MODULE.PARITY_LEDGER_TEST_MODULE
        )

        jobs = RUNNER_MODULE.select_jobs(arguments)

        self.assertEqual(tuple(case_id for job in jobs for case_id in job.case_ids), discovered)
        self.assertTrue(
            all(0 < len(job.case_ids) <= RUNNER_MODULE.DEFAULT_CASE_SHARD_SIZE for job in jobs)
        )

    def test_no_case_sharding_keeps_the_audited_module_monolithic(self) -> None:
        arguments = RUNNER_MODULE.parse_args(
            [
                "--module",
                RUNNER_MODULE.PARITY_LEDGER_TEST_MODULE,
                "--no-case-sharding",
                "--jobs",
                "1",
            ]
        )

        self.assertEqual(
            RUNNER_MODULE.select_jobs(arguments),
            [RUNNER_MODULE.TestJob(ROOT / RUNNER_MODULE.PARITY_LEDGER_TEST_MODULE)],
        )

    def test_worker_progress_uses_the_last_complete_checkpoint(self) -> None:
        log = self.fixture_root / "worker-progress.log"
        checkpoint = {
            "tests_started": 3,
            "tests_completed": 2,
            "current_test_id": "synthetic.Cases.test_c",
            "current_started_at": 1.5,
            "last_test_id": "synthetic.Cases.test_b",
            "last_elapsed_seconds": 0.25,
        }
        log.write_text(
            RUNNER_MODULE.PROGRESS_PREFIX
            + json.dumps(checkpoint, sort_keys=True)
            + "\n"
            + RUNNER_MODULE.PROGRESS_PREFIX
            + '{"tests_started": 4',
            encoding="utf-8",
        )

        progress = RUNNER_MODULE.worker_progress(log)

        self.assertIsNotNone(progress)
        assert progress is not None
        self.assertEqual(progress.tests_started, 3)
        self.assertEqual(progress.tests_completed, 2)
        self.assertEqual(progress.current_test_id, "synthetic.Cases.test_c")
        self.assertEqual(progress.last_test_id, "synthetic.Cases.test_b")

    def test_core_dumps_are_disabled_before_module_import_and_in_descendants(self) -> None:
        module = self.write_module(
            "test_core_policy.py",
            """\
import resource
import subprocess
import sys
import unittest

IMPORT_LIMITS = resource.getrlimit(resource.RLIMIT_CORE)

class CorePolicyTests(unittest.TestCase):
    def test_worker_and_descendant_cannot_create_core_files(self):
        self.assertEqual(IMPORT_LIMITS, (0, 0))
        child = subprocess.run(
            [sys.executable, "-c",
             "import resource; assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)"],
            check=False, timeout=5,
        )
        self.assertEqual(child.returncode, 0)
""",
        )
        # Give only the launcher child a nonzero soft limit. The regression
        # cannot emit a core and never changes this test process's limits.
        hard = resource.getrlimit(resource.RLIMIT_CORE)[1]
        if hard == 0:
            self.skipTest("parent hard core limit already forbids enabling cores")
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(
            [sys.executable, "-c",
             "import os, resource, sys; "
             "resource.setrlimit(resource.RLIMIT_CORE, (1, resource.getrlimit(resource.RLIMIT_CORE)[1])); "
             "os.execv(sys.executable, [sys.executable, *sys.argv[1:]])",
             str(RUNNER), "--module", self.relative(module), "--jobs", "1"],
            cwd=ROOT, env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        run_root = self.report_run_root(result)
        if run_root is not None:
            self.run_roots.append(run_root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("passed 1 modules / 1 tests", result.stdout)

    def test_failures_and_discovery_errors_are_nonzero_with_captured_logs(self) -> None:
        failure = self.write_module(
            "test_failure.py",
            """\
import unittest

class FailureTests(unittest.TestCase):
    def test_failure(self):
        print("synthetic failure payload")
        self.fail("synthetic failure")
""",
        )
        failed = self.invoke("--module", self.relative(failure), "--jobs", "1")
        self.assertEqual(failed.returncode, 1)
        self.assertIn("FAILED", failed.stdout)
        self.assertNotIn("synthetic failure payload", failed.stdout)
        failed_root = self.only_run_root()
        summary = json.loads((failed_root / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["modules"][0]["status"], "failed")
        self.assertEqual(summary["modules"][0]["exit_code"], 1)
        self.assertIn(
            "synthetic failure payload",
            (failed_root / "modules/001-test-failure/stdout.log").read_text(encoding="utf-8"),
        )

        malformed = self.write_module("test_malformed.py", "raise RuntimeError('synthetic discovery error')\n")
        discovery = self.invoke("--module", self.relative(malformed), "--jobs", "1")
        self.assertEqual(discovery.returncode, 1)
        self.assertIn("DISCOVERY-ERROR", discovery.stdout)

    def test_failure_traces_are_flushed_before_later_tests_run(self) -> None:
        module = self.write_module(
            "test_immediate.py",
            """\
import os
import unittest
from pathlib import Path

class ImmediateTests(unittest.TestCase):
    def test_a_failure(self):
        self.fail("immediate failure detail")

    def test_b_error(self):
        raise RuntimeError("immediate error detail")

    def test_c_subtest(self):
        with self.subTest(case="failure"):
            self.fail("immediate subtest detail")

    def test_d_prior_diagnostics_are_already_on_disk(self):
        log = Path(os.environ["CRABC_PYTHON_TEST_WORK_ROOT"]) / "stderr.log"
        text = log.read_text(encoding="utf-8")
        for message in ("AssertionError: immediate failure detail",
                        "RuntimeError: immediate error detail",
                        "AssertionError: immediate subtest detail"):
            self.assertIn(message, text)
""",
        )
        result = self.invoke("--module", self.relative(module), "--jobs", "1")
        self.assertEqual(result.returncode, 1)
        worker = self.only_run_root() / "modules/001-test-immediate"
        records = [line for line in (worker / "stdout.log").read_text().splitlines()
                   if line.startswith(RUNNER_MODULE.RESULT_PREFIX)]
        self.assertEqual(len(records), 1)
        payload = json.loads(records[0][len(RUNNER_MODULE.RESULT_PREFIX):])
        self.assertEqual(payload, {
            "tests_run": 4,
            "failures": 2,
            "errors": 1,
            "discovery_errors": 0,
            "completed_case_ids": [],
        })
        diagnostic = (worker / "stderr.log").read_text()
        self.assertEqual(diagnostic.count("AssertionError: immediate failure detail"), 1)
        self.assertEqual(diagnostic.count("RuntimeError: immediate error detail"), 1)
        self.assertEqual(diagnostic.count("AssertionError: immediate subtest detail"), 1)

    def test_timeout_kills_the_worker_process_group(self) -> None:
        timeout = self.write_module(
            "test_timeout.py",
            """\
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

class TimeoutTests(unittest.TestCase):
    def test_hangs_with_a_descendant(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        Path(os.environ["CRABC_PYTHON_TEST_WORK_ROOT"]).joinpath("child-pid").write_text(str(child.pid), encoding="utf-8")
        time.sleep(60)
""",
        )
        started = time.monotonic()
        result = self.invoke("--module", self.relative(timeout), "--jobs", "1", "--timeout", "0.2")
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("TIMEOUT", result.stdout)
        run_root = self.only_run_root()
        summary = json.loads((run_root / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["tests_run"], 1)
        self.assertEqual(summary["tests_completed"], 0)
        timeout_row = summary["modules"][0]
        self.assertEqual(
            timeout_row["current_test_id"],
            "test_timeout.TimeoutTests.test_hangs_with_a_descendant",
        )
        self.assertGreater(timeout_row["current_test_elapsed_seconds"], 0)
        child_pid = int((run_root / "modules/001-test-timeout/child-pid").read_text(encoding="utf-8"))
        self.assert_stopped(child_pid, "timeout left the worker descendant running")

    def test_clean_worker_exit_with_a_live_descendant_fails_closed(self) -> None:
        leak = self.write_module(
            "test_leak.py",
            """\
import os
import subprocess
import sys
import unittest
from pathlib import Path

class LeakTests(unittest.TestCase):
    def test_returns_without_reaping_a_descendant(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        Path(os.environ["CRABC_PYTHON_TEST_WORK_ROOT"]).joinpath("child-pid").write_text(str(child.pid), encoding="utf-8")
""",
        )

        result = self.invoke("--module", self.relative(leak), "--jobs", "1")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("PROCESS-GROUP-LEAK", result.stdout)
        run_root = self.only_run_root()
        child_pid = int((run_root / "modules/001-test-leak/child-pid").read_text(encoding="utf-8"))
        self.assert_stopped(child_pid, "normal worker exit left its descendant running")

    def test_cleanup_keeps_a_concurrent_unrelated_run_root(self) -> None:
        ready = self.fixture_root / "unrelated-ready"
        release = self.fixture_root / "unrelated-release"
        unrelated_module = self.write_module(
            "test_unrelated.py",
            """\
import os
import time
import unittest
from pathlib import Path

class UnrelatedTests(unittest.TestCase):
    def test_waits_for_its_owner(self):
        ready = Path(os.environ["UNRELATED_READY"])
        release = Path(os.environ["UNRELATED_RELEASE"])
        ready.write_text(os.environ["CRABC_PYTHON_TEST_RUN_ROOT"], encoding="utf-8")
        deadline = time.monotonic() + 10
        while not release.exists():
            if time.monotonic() >= deadline:
                self.fail("unrelated runner was not released")
            time.sleep(0.01)
""",
        )
        environment = dict(os.environ)
        environment.update(
            PYTHONDONTWRITEBYTECODE="1",
            UNRELATED_READY=str(ready),
            UNRELATED_RELEASE=str(release),
        )
        unrelated = subprocess.Popen(
            [sys.executable, str(RUNNER), "--module", self.relative(unrelated_module), "--jobs", "1"],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        def finish_unrelated() -> None:
            release.touch(exist_ok=True)
            try:
                unrelated.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                unrelated.terminate()
                unrelated.communicate()

        self.addCleanup(finish_unrelated)
        for _ in range(100):
            if ready.exists():
                break
            time.sleep(0.01)
        self.assertTrue(ready.is_file(), "unrelated runner did not start")
        unrelated_root = Path(ready.read_text(encoding="utf-8"))
        self.assertTrue(unrelated_root.is_relative_to(RUNS_ROOT.resolve()))
        self.assertFalse(unrelated_root.is_symlink())

        own_module = self.write_module(
            "test_owned.py",
            """\
import unittest

class OwnedTests(unittest.TestCase):
    def test_owned(self):
        self.assertTrue(True)
""",
        )
        result = self.invoke("--module", self.relative(own_module), "--jobs", "1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.remove_run_roots()
        self.assertTrue(unrelated_root.is_dir())
        self.assertIsNone(unrelated.poll())

        release.touch()
        stdout, stderr = unrelated.communicate(timeout=5)
        self.assertEqual(unrelated.returncode, 0, stdout + stderr)
        self.assertTrue(unrelated_root.is_dir())
        self.remove_owned_run_root(unrelated_root)

    def test_malformed_worker_protocol_records_fail_closed(self) -> None:
        for name, payload in (("test_protocol_list.py", "[]"), ("test_protocol_bool.py", '{"tests_run":true,"failures":0,"errors":0,"discovery_errors":0}')):
            with self.subTest(module=name):
                module = self.write_module(
                    name,
                    f"""\
import os
import sys
import unittest

class ProtocolTests(unittest.TestCase):
    def test_replaces_the_worker_record(self):
        payload = {payload!r}
        print("CRABC_PYTHON_TEST_RESULT " + payload, flush=True)
        os._exit(0)
""",
                )
                result = self.invoke("--module", self.relative(module), "--jobs", "1")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("WORKER-PROTOCOL-ERROR", result.stdout)

    def test_nonfinite_timeouts_and_unreadable_walks_fail_closed(self) -> None:
        for timeout in ("nan", "inf", "-inf"):
            with self.subTest(timeout=timeout):
                result = self.invoke(
                    "--module", "scripts/tests/test_test_python.py", f"--timeout={timeout}"
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("finite", result.stderr)

        def unreadable_walk(_directory: Path, *, followlinks: bool, onerror: object):
            self.assertFalse(followlinks)
            assert callable(onerror)
            onerror(PermissionError(13, "Permission denied", str(self.fixture_root)))
            return iter(())

        with mock.patch.object(RUNNER_MODULE.os, "walk", side_effect=unreadable_walk):
            with self.assertRaisesRegex(RUNNER_MODULE.TestPythonError, "unable to read selected directory"):
                RUNNER_MODULE.module_paths_in_directory(self.fixture_root, "test_*.py")

    def test_symlinked_selection_is_rejected_before_allocating_a_run_root(self) -> None:
        escape = self.fixture_root / "escape"
        escape.symlink_to("/", target_is_directory=True)

        result = self.invoke("--directory", self.relative(escape), "--jobs", "1")

        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)
        self.assertEqual(self.run_roots, [])


if __name__ == "__main__":
    unittest.main()
