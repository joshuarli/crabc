#!/usr/bin/env python3
"""Executable isolation contracts for the native Lua static dispatcher."""

from __future__ import annotations

import concurrent.futures
import importlib.util
import json
import shutil
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER_PATH = ROOT / "compat/lua/run.py"
SPEC = importlib.util.spec_from_file_location("crabc_lua_dispatch_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class NativeStaticDispatcherTests(unittest.TestCase):
    """Exercise isolated producer state and latest-report publication directly."""

    scratch_root = ROOT / ".work" / "lua-static-dispatcher-host-tests"

    def setUp(self) -> None:
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="dispatcher-", dir=self.scratch_root))
        self.parent = self.temporary / "state-parent"
        self.latest = self.temporary / "reports" / "x86_64-static-latest.json"
        self.builder = self.temporary / "fake-builder.py"
        self.builder.write_text(
            textwrap.dedent(
                """\
                from pathlib import Path
                import sys

                output = Path(sys.argv[sys.argv.index("--output") + 1])
                output.mkdir(parents=True, exist_ok=False)
                (output / "producer.txt").write_text("private producer state\\n", encoding="utf-8")
                """
            ),
            encoding="utf-8",
        )
        self.addCleanup(self.cleanup)

    def cleanup(self) -> None:
        if self.temporary.exists() and not self.temporary.is_symlink():
            shutil.rmtree(self.temporary, ignore_errors=True)

    @staticmethod
    def passing_runner(args: object) -> dict[str, object]:
        report = getattr(args, "report")
        sysroot = getattr(args, "sysroot")
        assert (sysroot / "producer.txt").is_file()
        (report.parent / "runner.txt").write_text("private runner state\n", encoding="utf-8")
        return {"schema_version": 2, "runner": "fake-static-runner", "result": "pass", "passed": True}

    @staticmethod
    def failing_runner(args: object) -> dict[str, object]:
        report = getattr(args, "report")
        (report.parent / "runner.txt").write_text("private failed runner state\n", encoding="utf-8")
        return {"schema_version": 2, "runner": "fake-static-runner", "result": "fail", "passed": False}

    def dispatch(self, runner: object) -> tuple[dict[str, object], Path, Path | None]:
        return RUNNER.run_x86_static_dispatch(
            jobs=2,
            timeout=5.0,
            state_parent=self.parent,
            latest_report=self.latest,
            builder=self.builder,
            static_runner=runner,
        )

    def test_two_concurrent_invocations_get_distinct_state_and_valid_latest_report(self) -> None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            completed = list(executor.map(lambda _: self.dispatch(self.passing_runner), range(2)))
        states = {report_path.parent for _, report_path, _ in completed}
        self.assertEqual(len(states), 2)
        parent = self.parent.resolve()
        for report, report_path, latest in completed:
            state = report_path.parent
            self.assertTrue(state.is_relative_to(parent))
            self.assertTrue((state / "sysroot/producer.txt").is_file())
            self.assertTrue((state / "runner.txt").is_file())
            self.assertEqual(report["passed"], True)
            self.assertEqual(report["dispatcher"]["state_root"], str(state))
            self.assertEqual(json.loads(report_path.read_text())["passed"], True)
            self.assertEqual(latest, self.latest)
        self.assertEqual(json.loads(self.latest.read_text())["passed"], True)

    def test_failed_invocation_retains_private_report_without_replacing_latest(self) -> None:
        original = b'{"passed":true,"result":"pass","sentinel":"prior"}\n'
        self.latest.parent.mkdir(parents=True, exist_ok=True)
        self.latest.write_bytes(original)
        report, report_path, published = self.dispatch(self.failing_runner)
        self.assertIsNone(published)
        self.assertEqual(report["passed"], False)
        self.assertEqual(self.latest.read_bytes(), original)
        self.assertTrue((report_path.parent / "sysroot/producer.txt").is_file())
        self.assertEqual(json.loads(report_path.read_text())["result"], "fail")

    def test_failed_producer_still_retains_its_private_authoritative_report(self) -> None:
        original = b'{"passed":true,"result":"pass","sentinel":"prior"}\n'
        self.latest.parent.mkdir(parents=True, exist_ok=True)
        self.latest.write_bytes(original)
        report, report_path, published = RUNNER.run_x86_static_dispatch(
            jobs=2,
            timeout=5.0,
            state_parent=self.parent,
            latest_report=self.latest,
            builder=self.temporary / "missing-builder.py",
            static_runner=self.passing_runner,
        )
        self.assertIsNone(published)
        self.assertEqual(report["passed"], False)
        self.assertIsNone(report["dispatcher"]["producer"])
        self.assertIn("native Lua static sysroot builder is absent", str(report["error"]))
        self.assertEqual(self.latest.read_bytes(), original)
        self.assertEqual(json.loads(report_path.read_text())["result"], "fail")


if __name__ == "__main__":
    unittest.main()
