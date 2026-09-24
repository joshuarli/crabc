#!/usr/bin/env python3
"""Fail-closed contracts for the consumer.source-build qualification case."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/lua/qualify_source_build.py"
SPEC = importlib.util.spec_from_file_location("lua_qualify_source_build", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
QUALIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = QUALIFY
SPEC.loader.exec_module(QUALIFY)

SOURCE = {"revision": "a" * 40, "source_sha256": "b" * 64}


def campaign(statuses: dict[str, str]) -> dict[str, object]:
    """Return the campaign-report family rows this runner consumes."""

    dependencies = {
        "oracle.musl-toolchain": [],
        "sysroot.owned-artifact": ["oracle.musl-toolchain"],
        "compat.loader-corpus": ["oracle.musl-toolchain", "sysroot.owned-artifact"],
        "consumer.rust-std-lto": ["sysroot.owned-artifact", "compat.loader-corpus"],
        "consumer.source-build": [
            "oracle.musl-toolchain", "sysroot.owned-artifact", "consumer.rust-std-lto"
        ],
    }
    return {
        "families": [
            {"id": family, "status": statuses.get(family, "foundation-verified"), "dependencies": edges}
            for family, edges in dependencies.items()
        ]
    }


class QualificationCaseTests(unittest.TestCase):
    def run_main(self) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = QUALIFY.main([])
        return status, stdout.getvalue(), stderr.getvalue()

    def forbid_execution(self) -> contextlib.ExitStack:
        stack = contextlib.ExitStack()
        for owner, name in (
            (QUALIFY.LUA, "run_x86_static_dispatch"),
            (QUALIFY.DYNAMIC, "run_dynamic_dispatch"),
            (QUALIFY.ADMISSION, "validate"),
        ):
            stack.enter_context(mock.patch.object(
                owner, name, side_effect=AssertionError(f"{name} must not start")
            ))
        return stack

    def test_open_transitive_prerequisites_refuse_before_any_lua_build(self) -> None:
        report = campaign({"sysroot.owned-artifact": "planned", "compat.loader-corpus": "planned"})
        with (
            self.forbid_execution(),
            mock.patch.object(QUALIFY.CASE, "clean_source_identity", return_value=SOURCE),
            mock.patch.object(QUALIFY.CASE.CAMPAIGN, "build_report", return_value=report),
        ):
            status, stdout, stderr = self.run_main()
        self.assertEqual(status, 1)
        self.assertNotIn(QUALIFY.PASS_MARKER, stdout)
        self.assertIn(
            "prerequisites are not foundation-verified: sysroot.owned-artifact, compat.loader-corpus\n",
            stderr,
        )

    def test_dirty_source_refuses_before_reading_prerequisites_or_building(self) -> None:
        with (
            self.forbid_execution(),
            mock.patch.object(
                QUALIFY.CASE.PRODUCT, "require_clean_source",
                side_effect=QUALIFY.CASE.PRODUCT.QualificationError("qualification publication requires clean source"),
            ),
            mock.patch.object(
                QUALIFY.CASE.CAMPAIGN, "build_report", side_effect=AssertionError("prerequisites read")
            ),
        ):
            status, stdout, stderr = self.run_main()
        self.assertEqual(status, 1)
        self.assertNotIn(QUALIFY.PASS_MARKER, stdout)
        self.assertIn("clean source", stderr)

    def closed_run(self, *, after: dict[str, str] = SOURCE, admitted: dict[str, str] = SOURCE):
        calls: list[str] = []

        def static(**arguments: object):
            calls.append("static")
            self.assertEqual(arguments, {"jobs": QUALIFY.JOBS, "timeout": QUALIFY.COMMAND_TIMEOUT})
            return {"passed": True, "result": "pass"}, Path("/state/static/report.json"), Path("/latest/static.json")

        def dynamic(**arguments: object):
            calls.append("dynamic")
            self.assertEqual(
                arguments, {"jobs": QUALIFY.JOBS, "timeout": QUALIFY.COMMAND_TIMEOUT, "offline": False}
            )
            return {"passed": True, "result": "pass"}, Path("/state/dynamic/report.json"), Path("/latest/dynamic.json")

        def admission():
            calls.append("admission")
            return {"source_identity": admitted, "static": {}, "dynamic": {}}

        identities = iter((SOURCE, after))
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(QUALIFY.CASE, "clean_source_identity", side_effect=lambda: next(identities)))
        stack.enter_context(mock.patch.object(QUALIFY.CASE.CAMPAIGN, "build_report", return_value=campaign({})))
        stack.enter_context(mock.patch.object(QUALIFY.LUA, "run_x86_static_dispatch", side_effect=static))
        stack.enter_context(mock.patch.object(QUALIFY.DYNAMIC, "run_dynamic_dispatch", side_effect=dynamic))
        stack.enter_context(mock.patch.object(QUALIFY.ADMISSION, "validate", side_effect=admission))
        return stack, calls

    def test_closed_prerequisites_run_the_frozen_roster_then_emit_one_final_marker(self) -> None:
        stack, calls = self.closed_run()
        with stack:
            status, stdout, _stderr = self.run_main()
        self.assertEqual(status, 0)
        self.assertEqual(calls, ["static", "dynamic", "admission"])
        lines = [line for line in stdout.splitlines() if line]
        self.assertEqual(lines.count(QUALIFY.PASS_MARKER), 1)
        self.assertEqual(lines[-1], QUALIFY.PASS_MARKER)

    def test_admission_bound_to_other_source_is_rejected(self) -> None:
        stack, _calls = self.closed_run(admitted={**SOURCE, "source_sha256": "c" * 64})
        with stack:
            status, stdout, stderr = self.run_main()
        self.assertEqual(status, 1)
        self.assertNotIn(QUALIFY.PASS_MARKER, stdout)
        self.assertIn("different source", stderr)

    def test_source_change_during_the_case_is_rejected(self) -> None:
        stack, _calls = self.closed_run(after={**SOURCE, "revision": "d" * 40})
        with stack:
            status, stdout, stderr = self.run_main()
        self.assertEqual(status, 1)
        self.assertNotIn(QUALIFY.PASS_MARKER, stdout)
        self.assertIn("source changed", stderr)

    def test_failed_lane_stops_before_later_lanes(self) -> None:
        stack, calls = self.closed_run()
        with stack, mock.patch.object(
            QUALIFY.LUA,
            "run_x86_static_dispatch",
            return_value=({"passed": False, "result": "fail"}, Path("/state/static/report.json"), None),
        ):
            status, stdout, stderr = self.run_main()
        self.assertEqual(status, 1)
        self.assertEqual(calls, [])
        self.assertNotIn(QUALIFY.PASS_MARKER, stdout)
        self.assertIn("/state/static/report.json", stderr)

    def test_runner_imports_its_siblings_under_the_scrubbed_qualification_environment(self) -> None:
        # The ordered qualification runner starts cases with PYTHONSAFEPATH=1,
        # so the script directory is not implicitly importable.
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONSAFEPATH": "1", "PYTHONNOUSERSITE": "1"}
        completed = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--help"],
            cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))


class QualificationDeclarationTests(unittest.TestCase):
    def test_checked_in_gate_pins_only_this_case_and_stays_blocked_by_planned_predecessors(self) -> None:
        sys.path.insert(0, str(ROOT / "compat/x86_64"))
        import generate_qualification_manifest as manifest
        import run_qualification_manifest as prefix

        report = manifest.load_contract()
        gates = {gate["id"]: gate for gate in report["promotion_chain"]}
        gate = gates["consumer.source-build"]
        self.assertEqual(gate["state"], "ready")
        cases = manifest.load_json(ROOT / gate["case_manifest"], "source-build cases")["cases"]
        self.assertEqual(
            [(case["id"], case["command"], case["expected_stdout_line"]) for case in cases],
            [(
                "lua-frozen-source-build",
                ["python3", "compat/lua/qualify_source_build.py"],
                QUALIFY.PASS_MARKER,
            )],
        )
        self.assertFalse(report["promotion_ready"])
        self.assertIn("consumer.source-build", report["incomplete_gates"])
        with self.assertRaisesRegex(prefix.QualificationRunError, "planned dependencies: compat.abi-differential"):
            prefix.select_promotion_prefix(report, "consumer.source-build")


if __name__ == "__main__":
    unittest.main()
