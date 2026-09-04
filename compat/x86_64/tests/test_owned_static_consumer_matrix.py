#!/usr/bin/env python3
"""Executable process-isolation contracts for the static consumer matrix."""

from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "compat" / "x86_64" / "owned_static_consumer_matrix.py"
SCRATCH_ROOT = ROOT / ".work" / "x86_64" / "owned-static-consumer-matrix-tests"


class OwnedStaticConsumerMatrixTests(unittest.TestCase):
    """Exercise the helper through child processes, never source-text matching."""

    def setUp(self) -> None:
        SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
        self.fixture_root = Path(
            tempfile.mkdtemp(prefix="consumer-matrix-", dir=SCRATCH_ROOT)
        )
        self.state_root = self.fixture_root / "state"
        self.state_root.mkdir()
        self.addCleanup(self.remove_fixture_root)

    def remove_fixture_root(self) -> None:
        try:
            resolved = self.fixture_root.resolve(strict=True)
        except FileNotFoundError:
            return
        scratch = SCRATCH_ROOT.resolve(strict=True)
        if (
            not self.fixture_root.is_symlink()
            and resolved == self.fixture_root
            and resolved.is_relative_to(scratch)
        ):
            shutil.rmtree(resolved, ignore_errors=True)

    def write_child(self, name: str, body: str) -> list[str]:
        path = self.fixture_root / name
        path.write_text(body, encoding="utf-8")
        return [sys.executable, str(path)]

    def write_manifest(self, jobs: list[dict[str, object]]) -> Path:
        manifest = self.state_root / "jobs.json"
        manifest.write_text(
            json.dumps({"schema": 1, "jobs": jobs}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return manifest

    def command(
        self,
        manifest: Path,
        logs: Path,
        *,
        workers: int | None = None,
        timeout: float = 2.0,
    ) -> list[str]:
        command = [
            sys.executable,
            str(HELPER),
            "--state-root",
            str(self.state_root),
            "--manifest",
            str(manifest),
            "--log-directory",
            str(logs),
            "--timeout",
            str(timeout),
        ]
        if workers is not None:
            command.extend(("--workers", str(workers)))
        return command

    def invoke(
        self,
        manifest: Path,
        logs: Path,
        *,
        workers: int | None = None,
        timeout: float = 2.0,
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            self.command(manifest, logs, workers=workers, timeout=timeout),
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )

    def summary(self, logs: Path) -> dict[str, object]:
        return json.loads((logs / "summary.json").read_text(encoding="utf-8"))

    def assert_stopped(self, pid: int, message: str) -> None:
        status = Path(f"/proc/{pid}/stat")
        for _ in range(100):
            if not status.exists():
                return
            try:
                state = status.read_text(encoding="utf-8").rsplit(")", 1)[1].split()[0]
            except (IndexError, OSError):
                return
            if state == "Z":
                return
            time.sleep(0.02)
        self.fail(message)

    def wait_for(self, path: Path, message: str) -> None:
        deadline = time.monotonic() + 5.0
        while not path.exists():
            if time.monotonic() >= deadline:
                self.fail(message)
            time.sleep(0.02)

    def test_failure_is_aggregated_and_later_jobs_still_run(self) -> None:
        failure_marker = self.state_root / "failure-ran"
        success_marker = self.state_root / "success-ran"
        failure = self.write_child(
            "failure.py",
            """\
from pathlib import Path
import sys

Path(sys.argv[1]).write_text("failure", encoding="utf-8")
print("failure-output", flush=True)
raise SystemExit(17)
""",
        )
        success = self.write_child(
            "success.py",
            """\
from pathlib import Path
import sys

Path(sys.argv[1]).write_text("success", encoding="utf-8")
print("success-output", flush=True)
""",
        )
        manifest = self.write_manifest(
            [
                {"name": "failure", "argv": [*failure, str(failure_marker)]},
                {"name": "success", "argv": [*success, str(success_marker)]},
            ]
        )
        logs = self.state_root / "failure-logs"

        result = self.invoke(manifest, logs, workers=1)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(failure_marker.is_file())
        self.assertTrue(success_marker.is_file())
        summary = self.summary(logs)
        self.assertEqual(
            [record["status"] for record in summary["jobs"]], ["failed", "passed"]
        )
        self.assertEqual(summary["jobs"][0]["exit_code"], 17)
        self.assertIn("failure-output", (logs / "failure.log").read_text(encoding="utf-8"))
        self.assertIn("success-output", (logs / "success.log").read_text(encoding="utf-8"))

    def test_timeout_kills_the_whole_owned_process_group(self) -> None:
        child_pid = self.state_root / "timeout-child-pid"
        timeout = self.write_child(
            "timeout.py",
            """\
from pathlib import Path
import subprocess
import sys
import time

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path(sys.argv[1]).write_text(str(child.pid), encoding="utf-8")
time.sleep(60)
""",
        )
        manifest = self.write_manifest(
            [{"name": "timeout", "argv": [*timeout, str(child_pid)]}]
        )
        logs = self.state_root / "timeout-logs"

        started = time.monotonic()
        result = self.invoke(manifest, logs, workers=1, timeout=0.2)

        self.assertLess(time.monotonic() - started, 5.0)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.summary(logs)["jobs"][0]["status"], "timeout")
        self.assert_stopped(
            int(child_pid.read_text(encoding="utf-8")),
            "timeout left an owned child process running",
        )

    def test_clean_leader_exit_with_a_descendant_fails_closed(self) -> None:
        child_pid = self.state_root / "leak-child-pid"
        leak = self.write_child(
            "leak.py",
            """\
from pathlib import Path
import subprocess
import sys

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path(sys.argv[1]).write_text(str(child.pid), encoding="utf-8")
""",
        )
        manifest = self.write_manifest(
            [{"name": "leak", "argv": [*leak, str(child_pid)]}]
        )
        logs = self.state_root / "leak-logs"

        result = self.invoke(manifest, logs, workers=1)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(
            self.summary(logs)["jobs"][0]["status"], "process-group-leak"
        )
        self.assert_stopped(
            int(child_pid.read_text(encoding="utf-8")),
            "clean leader exit left an owned descendant running",
        )

    def test_interrupt_cancels_all_active_job_groups_before_returning(self) -> None:
        ready = self.state_root / "cancel-ready"
        child_pid = self.state_root / "cancel-child-pid"
        sleeper = self.write_child(
            "sleeper.py",
            """\
from pathlib import Path
import subprocess
import sys
import time

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
Path(sys.argv[1]).write_text(str(child.pid), encoding="utf-8")
Path(sys.argv[2]).write_text("ready", encoding="utf-8")
time.sleep(60)
""",
        )
        manifest = self.write_manifest(
            [{"name": "sleeper", "argv": [*sleeper, str(child_pid), str(ready)]}]
        )
        logs = self.state_root / "cancel-logs"
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"

        matrix = subprocess.Popen(
            self.command(manifest, logs, workers=1, timeout=30),
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(self.stop_matrix, matrix)
        self.wait_for(ready, "matrix did not start its owned child")
        matrix.send_signal(signal.SIGTERM)
        stdout, stderr = matrix.communicate(timeout=5)

        self.assertEqual(matrix.returncode, 128 + signal.SIGTERM, stdout + stderr)
        self.assertEqual(self.summary(logs)["interrupted_by"], signal.SIGTERM)
        self.assert_stopped(
            int(child_pid.read_text(encoding="utf-8")),
            "interrupt returned before cancelling the owned descendant",
        )

    def stop_matrix(self, matrix: subprocess.Popen[str]) -> None:
        if matrix.poll() is None:
            matrix.kill()
        try:
            matrix.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            matrix.kill()
            matrix.communicate()

    def test_parallel_jobs_keep_logs_and_file_outputs_private(self) -> None:
        rendezvous = self.state_root / "rendezvous"
        left = self.state_root / "left"
        right = self.state_root / "right"
        left.mkdir()
        right.mkdir()
        program = self.write_child(
            "isolated.py",
            """\
from pathlib import Path
import sys
import time

name = sys.argv[1]
private = Path(sys.argv[2])
rendezvous = Path(sys.argv[3])
rendezvous.mkdir(exist_ok=True)
(private / "value").write_text(name, encoding="utf-8")
(rendezvous / (name + ".ready")).write_text("ready", encoding="utf-8")
deadline = time.monotonic() + 3.0
while len(list(rendezvous.glob("*.ready"))) < 2:
    if time.monotonic() >= deadline:
        raise SystemExit("parallel rendezvous timed out")
    time.sleep(0.01)
print("isolated-output:" + name, flush=True)
""",
        )
        manifest = self.write_manifest(
            [
                {"name": "left", "argv": [*program, "left", str(left), str(rendezvous)]},
                {"name": "right", "argv": [*program, "right", str(right), str(rendezvous)]},
            ]
        )
        logs = self.state_root / "isolation-logs"

        result = self.invoke(manifest, logs, workers=2)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((left / "value").read_text(encoding="utf-8"), "left")
        self.assertEqual((right / "value").read_text(encoding="utf-8"), "right")
        left_log = (logs / "left.log").read_text(encoding="utf-8")
        right_log = (logs / "right.log").read_text(encoding="utf-8")
        self.assertIn("isolated-output:left", left_log)
        self.assertNotIn("isolated-output:right", left_log)
        self.assertIn("isolated-output:right", right_log)
        self.assertNotIn("isolated-output:left", right_log)
        log_mode = (logs / "left.log").stat().st_mode
        self.assertTrue(log_mode & stat.S_IRGRP)
        self.assertFalse(log_mode & stat.S_IROTH)
        summary = self.summary(logs)
        self.assertEqual(summary["workers"], 2)
        self.assertEqual([record["status"] for record in summary["jobs"]], ["passed", "passed"])

    def test_default_worker_count_and_cap_are_enforced(self) -> None:
        success = self.write_child("one.py", "print('one', flush=True)\n")
        manifest = self.write_manifest([{"name": "one", "argv": success}])
        logs = self.state_root / "default-logs"

        default = self.invoke(manifest, logs, workers=None)

        self.assertEqual(default.returncode, 0, default.stdout + default.stderr)
        self.assertEqual(self.summary(logs)["workers"], 4)
        rejected = self.invoke(
            manifest,
            self.state_root / "rejected-logs",
            workers=9,
        )
        self.assertEqual(rejected.returncode, 2, rejected.stdout + rejected.stderr)
        self.assertFalse((self.state_root / "rejected-logs").exists())

    def test_symlinked_log_directory_is_rejected_before_a_job_can_escape(self) -> None:
        marker = self.fixture_root / "job-ran"
        outside = self.fixture_root / "outside-state-root"
        outside.mkdir()
        escaped_logs = self.state_root / "escaped-logs"
        escaped_logs.symlink_to(outside, target_is_directory=True)
        success = self.write_child(
            "escape.py",
            "from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('ran')\n",
        )
        manifest = self.write_manifest(
            [{"name": "escape", "argv": [*success, str(marker)]}]
        )

        result = self.invoke(manifest, escaped_logs, workers=1)

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
