#!/usr/bin/env python3
"""Behavioral contracts for the isolated Python unittest runner."""

from __future__ import annotations

import importlib.util
import os
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
            if path.is_relative_to(RUNS_ROOT) and not path.is_symlink():
                shutil.rmtree(path, ignore_errors=True)

    def relative(self, path: Path) -> str:
        return path.relative_to(ROOT).as_posix()

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        before = set(RUNS_ROOT.glob("run-*")) if RUNS_ROOT.exists() else set()
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
        after = set(RUNS_ROOT.glob("run-*")) if RUNS_ROOT.exists() else set()
        created = after - before
        self.assertLessEqual(len(created), 1, result.stdout + result.stderr)
        self.run_roots.extend(created)
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
        (coordinate / (Path(__file__).stem + ".started")).write_text(str(time.monotonic()), encoding="utf-8")
        print("synthetic child output must stay in the captured log")
        time.sleep(0.6)
"""
        (suite / "test_one.py").write_text(body, encoding="utf-8")
        (suite / "test_two.py").write_text(body, encoding="utf-8")

        result = self.invoke("--directory", self.relative(suite), "--jobs", "2")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("passed 2 modules / 2 tests", result.stdout)
        self.assertNotIn("synthetic child output", result.stdout)
        run_root = self.only_run_root()
        starts = sorted(
            float(path.read_text(encoding="utf-8"))
            for path in (run_root / "coordination").glob("*.started")
        )
        self.assertEqual(len(starts), 2)
        self.assertLess(starts[1] - starts[0], 0.35)
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
        self.assertIn(
            "synthetic failure payload",
            (failed_root / "modules/001-test-failure/stdout.log").read_text(encoding="utf-8"),
        )

        malformed = self.write_module("test_malformed.py", "raise RuntimeError('synthetic discovery error')\n")
        discovery = self.invoke("--module", self.relative(malformed), "--jobs", "1")
        self.assertEqual(discovery.returncode, 1)
        self.assertIn("DISCOVERY-ERROR", discovery.stdout)

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
