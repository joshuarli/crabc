#!/usr/bin/env python3
"""Host-side contract tests for the native dynamic Lua dispatcher."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
RUNNER_PATH = ROOT / "compat/lua/run_x86_dynamic.py"
if str(RUNNER_PATH.parent) not in sys.path:
    sys.path.insert(0, str(RUNNER_PATH.parent))
SPEC = importlib.util.spec_from_file_location("crabc_lua_dynamic_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class NativeDynamicDispatcherTests(unittest.TestCase):
    """Exercise publication and installed/extracted lane acceptance contracts."""

    scratch_root = ROOT / ".work" / "lua-dynamic-dispatcher-host-tests"

    def setUp(self) -> None:
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="dispatcher-", dir=self.scratch_root))
        self.parent = self.temporary / "state-parent"
        self.latest = self.temporary / "reports" / "x86_64-dynamic-latest.json"
        self.addCleanup(self.cleanup)

    def cleanup(self) -> None:
        if self.temporary.exists() and not self.temporary.is_symlink():
            shutil.rmtree(self.temporary, ignore_errors=True)

    @staticmethod
    def lane(label: str, *, passed: bool) -> dict[str, object]:
        artifacts: dict[str, object] = {}
        for name in ("liblua", "lua", "luac", "probe", "failure", "missing_symbol"):
            digest = hashlib.sha256(f"{label}:{name}".encode("utf-8")).hexdigest()
            artifacts[name] = {"artifact": {"sha256": digest}}
        return {"passed": passed, "candidate": {"artifacts": artifacts}}

    def dispatch(
        self, lanes: list[dict[str, object]]
    ) -> tuple[dict[str, object], Path, Path | None, mock.Mock, mock.Mock]:
        command = mock.Mock(return_value={"status": 0})
        dynamic_lane = mock.Mock(side_effect=lanes)
        with (
            mock.patch.object(RUNNER, "require_regular", side_effect=lambda path, _description: path),
            mock.patch.object(RUNNER, "command", command),
            mock.patch.object(RUNNER, "run_dynamic_lane", dynamic_lane),
        ):
            report, report_path, published = RUNNER.run_dynamic_dispatch(
                jobs=2,
                timeout=5.0,
                offline=False,
                state_parent=self.parent,
                latest_report=self.latest,
            )
        return report, report_path, published, command, dynamic_lane

    def test_failed_lane_retains_private_report_without_replacing_latest(self) -> None:
        original = b'{"passed":true,"result":"pass","sentinel":"prior"}\n'
        self.latest.parent.mkdir(parents=True, exist_ok=True)
        self.latest.write_bytes(original)
        failed = self.lane("identical-graph", passed=False)
        extracted = self.lane("identical-graph", passed=True)

        report, report_path, published, command, dynamic_lane = self.dispatch([failed, extracted])

        self.assertIsNone(published)
        self.assertFalse(report["passed"])
        self.assertEqual(report["result"], "fail")
        self.assertEqual(report["installed"], failed)
        self.assertEqual(report["extracted"], extracted)
        self.assertEqual(report["reproducibility"]["status"], "passed")
        self.assertEqual(self.latest.read_bytes(), original)
        self.assertEqual(json.loads(report_path.read_text(encoding="utf-8"))["passed"], False)
        self.assertEqual(command.call_count, 3)
        self.assertEqual([call.kwargs["offline"] for call in dynamic_lane.call_args_list], [False, True])

    def test_artifact_hash_drift_rejects_reproducibility_and_latest_publication(self) -> None:
        original = b'{"passed":true,"result":"pass","sentinel":"prior"}\n'
        self.latest.parent.mkdir(parents=True, exist_ok=True)
        self.latest.write_bytes(original)
        installed = self.lane("installed", passed=True)
        extracted = self.lane("extracted", passed=True)

        report, report_path, published, _, _ = self.dispatch([installed, extracted])

        self.assertIsNone(published)
        self.assertFalse(report["passed"])
        self.assertEqual(report["reproducibility"]["status"], "rejected")
        self.assertNotEqual(
            report["reproducibility"]["installed_artifacts"],
            report["reproducibility"]["extracted_artifacts"],
        )
        self.assertEqual(self.latest.read_bytes(), original)
        self.assertEqual(json.loads(report_path.read_text(encoding="utf-8"))["result"], "fail")


class NativeDynamicSysrootInputTests(unittest.TestCase):
    """The dynamic sysroot manifest is an exact candidate input roster."""

    scratch_root = ROOT / ".work" / "lua-dynamic-sysroot-host-tests"

    def setUp(self) -> None:
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="sysroot-", dir=self.scratch_root))
        self.addCleanup(self.cleanup)

    def cleanup(self) -> None:
        if self.temporary.exists() and not self.temporary.is_symlink():
            shutil.rmtree(self.temporary, ignore_errors=True)

    def test_manifest_rejects_an_undeclared_runtime_payload(self) -> None:
        libc = self.temporary / "usr/lib/libc.so"
        libc.parent.mkdir(parents=True)
        libc.write_bytes(b"declared runtime payload\n")
        unowned = self.temporary / "usr/lib/foreign-runtime.so"
        unowned.write_bytes(b"must not enter a candidate sysroot\n")
        manifest = {
            "schema": 1,
            "format": RUNNER.FORMAT,
            "target": "x86_64-unknown-linux-musl",
            "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"},
            "files": {"usr/lib/libc.so": RUNNER.LUA.sha256_file(libc)},
        }
        manifest_path = self.temporary / "share/crabc/manifest.json"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "payload roster drifted"):
            RUNNER.owned_dynamic_sysroot(self.temporary)


if __name__ == "__main__":
    unittest.main()
