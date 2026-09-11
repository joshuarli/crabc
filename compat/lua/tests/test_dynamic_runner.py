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


class NativeDynamicReceiptTests(unittest.TestCase):
    """The Lua graph accepts either closed driver sidecar schema."""

    scratch_root = ROOT / ".work" / "lua-dynamic-receipt-host-tests"

    def setUp(self) -> None:
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="receipt-", dir=self.scratch_root))
        self.addCleanup(shutil.rmtree, self.temporary, ignore_errors=True)
        self.product = self.temporary / "product"
        library = self.product / "usr/lib"
        library.mkdir(parents=True)
        self.runtime = {}
        for key, name in (
            ("crti.o", "crti.o"), ("libc.so", "libc.so"), ("crtn.o", "crtn.o"),
            ("Scrt1.o", "Scrt1.o"), ("crt1.o", "crt1.o"), ("attach", "crabc-dynamic-attach.o"),
            ("builtins", "libcrabc-builtins.a"),
        ):
            path = library / name
            path.write_bytes(f"{key} payload\n".encode())
            self.runtime[key] = path
        self.output = self.temporary / "application/liblua.so.5.4"
        self.output.parent.mkdir()
        self.output.write_bytes(b"Lua dynamic output\n")
        self.object = self.temporary / "objects/lua.o"
        self.object.parent.mkdir()
        self.object.write_bytes(b"Lua object\n")
        self.manifest = self.product / "share/crabc/manifest.json"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_bytes(b"owned product manifest\n")
        self.receipt = Path(f"{self.output}.crabc-link.json")

    def record(self, schema: int) -> dict[str, object]:
        runtime = [self.runtime[name] for name in ("crti.o", "libc.so", "crtn.o")]
        archive = self.runtime["builtins"]
        record: dict[str, object] = {
            "schema": schema,
            "format": RUNNER.FORMAT,
            "mode": "shared",
            "binding": "now",
            "runtime_imports": [],
            "application_runpath": "/usr/lib",
            "output_path": str(self.output.resolve()),
            "output_sha256": RUNNER.LUA.sha256_file(self.output),
            "manifest_sha256": RUNNER.LUA.sha256_file(self.manifest),
            "application_dsos": {},
            "owned_runtime_inputs": sorted(path.relative_to(self.product).as_posix() for path in [*runtime, archive]),
            "input_receipts": [
                {"path": str(path), "sha256": RUNNER.LUA.sha256_file(path)}
                for path in [*runtime, self.object.resolve(), archive]
            ],
            "resolved_linker": {"path": "/owned/ld.lld", "sha256": "0" * 64},
            "link_command": ["/owned/ld.lld"],
            "link_trace": [*(str(path) for path in runtime), str(self.object.resolve())],
            "campaign_complete": False,
        }
        if schema == 2:
            record.update({
                "application_search_kind": "runpath",
                "application_rpath": None,
                "application_hash_style": "sysv",
            })
        return record

    def audit(self, record: dict[str, object]) -> dict[str, object]:
        self.receipt.write_text(json.dumps(record), encoding="utf-8")
        return RUNNER.audit_dynamic_receipt(
            sysroot=self.product,
            runtime=self.runtime,
            mode="shared",
            objects=[self.object],
            application_dsos=[],
            output=self.output,
        )

    def test_audit_accepts_closed_schema_one_and_schema_two_receipts(self) -> None:
        for schema in (1, 2):
            with self.subTest(schema=schema):
                self.assertEqual(self.audit(self.record(schema))["status"], "passed")

    def test_audit_rejects_unversioned_mixed_and_non_sysv_search_receipts(self) -> None:
        valid = self.record(2)
        for changed in (
            {key: value for key, value in valid.items() if key != "schema"},
            {**self.record(1), "application_search_kind": "runpath"},
            {**valid, "application_hash_style": "gnu"},
            {**valid, "application_search_kind": "rpath", "application_runpath": None,
             "application_rpath": "/usr/lib"},
        ):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "schema|fields|search-path"):
                    self.audit(changed)


if __name__ == "__main__":
    unittest.main()
