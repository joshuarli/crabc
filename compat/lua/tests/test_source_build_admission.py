#!/usr/bin/env python3
"""Tests for physical and source-bound Lua admission reports."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "compat/lua/source_build_admission.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("lua_source_build_admission", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ADMISSION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADMISSION
SPEC.loader.exec_module(ADMISSION)


class SourceBuildAdmissionTests(unittest.TestCase):
    def test_lane_report_with_stale_source_identity_is_rejected(self) -> None:
        work = ROOT / ".work/x86_64/lua-admission-tests"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="report-", dir=work) as temporary:
            state = Path(temporary)
            authoritative = state / "report.json"
            latest = state / "latest.json"
            payload = {
                "runner": "crabc-lua-native-x86-static-source-build",
                "result": "pass",
                "passed": True,
                "dispatcher": {
                    "state_root": str(state),
                    "authoritative_report": str(authoritative),
                    "latest_report": str(latest),
                    "source_identity": {"revision": "0" * 40, "source_sha256": "0" * 64},
                },
            }
            encoded = json.dumps(payload).encode()
            authoritative.write_bytes(encoded)
            latest.write_bytes(encoded)
            with mock.patch.object(ADMISSION.LUA, "current_source_identity", return_value={
                "revision": "1" * 40,
                "source_sha256": "1" * 64,
            }):
                with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "stale source"):
                    ADMISSION.read_report(latest, "crabc-lua-native-x86-static-source-build")

    def test_pass_flag_cannot_override_changed_raw_workload_output(self) -> None:
        def stream(data: bytes) -> dict[str, object]:
            import hashlib

            return {
                "byte_length": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "hex": data.hex(),
                "text": data.decode("utf-8", errors="replace"),
            }

        comparison = {
            "passed": True,
            "normalization": "none",
            "status_match": True,
            "stdout_match": True,
            "stderr_match": True,
            "reference": {
                "status": 0,
                "timed_out": False,
                "stdout": stream(b"expected\n"),
                "stderr": stream(b""),
            },
            "candidate": {
                "status": 0,
                "timed_out": False,
                "stdout": stream(b"edited\n"),
                "stderr": stream(b""),
            },
        }
        with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "raw outcomes"):
            ADMISSION.validate_result_comparison(comparison)

    def test_pass_flag_cannot_override_failed_retained_command(self) -> None:
        command = {
            "command": ["/bin/true"],
            "cwd": str(ROOT),
            "status": 1,
            "stdout": {"byte_length": 0, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hex": "", "text": ""},
            "stderr": {"byte_length": 0, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hex": "", "text": ""},
        }
        with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "command did not complete"):
            ADMISSION.validate_report_records({"passed": True, "producer": command})

    def test_static_product_manifest_must_match_the_lane_report(self) -> None:
        ADMISSION.WORK.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="product-", dir=ADMISSION.WORK) as temporary:
            root = Path(temporary)
            report = {
                "dispatcher": {"state_root": str(root)},
                "environment": {"sysroot_manifest": {"files": {"libc.a": "0" * 64}}},
            }
            observed = {"files": {"libc.a": "1" * 64}}
            with (
                mock.patch.object(ADMISSION, "read_report", return_value=report),
                mock.patch.object(
                    ADMISSION.LUA,
                    "owned_static_sysroot",
                    return_value=(root, root / "cc", {}, observed),
                ),
            ):
                with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "product manifest differ"):
                    ADMISSION.admit_static()


if __name__ == "__main__":
    unittest.main()
