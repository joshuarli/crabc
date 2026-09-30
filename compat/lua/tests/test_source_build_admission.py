#!/usr/bin/env python3
"""Tests for physical and source-bound Lua admission reports."""

from __future__ import annotations

import contextlib
import importlib.util
import io
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

    @contextlib.contextmanager
    def selected_reports(self):
        ADMISSION.WORK.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="selected-", dir=ADMISSION.WORK) as temporary:
            work = Path(temporary)
            source = {"revision": "1" * 40, "source_sha256": "2" * 64}
            artifact = work / "program"
            artifact.write_bytes(b"retained Lua application artifact")
            artifact_record = ADMISSION.LUA.artifact_record(artifact)
            manifest = {"files": {"program": artifact_record["sha256"]}}
            static = work / "static"
            dynamic = work / "dynamic"
            for product in (static / "sysroot", dynamic / "sysroot", dynamic / "extracted"):
                directory = product / "share/crabc"
                directory.mkdir(parents=True)
                (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            workloads = {"source": {"passed": True}, "bytecode": {"passed": True}}
            hashes = {name: artifact_record["sha256"] for name in (
                "liblua", "lua", "luac", "probe", "failure", "missing_symbol"
            )}
            lane = {
                "passed": True,
                "environment": {"sysroot_manifest": manifest},
                "workloads": workloads,
                "candidate": {"artifacts": {
                    name: {"artifact": artifact_record} for name in hashes
                }},
            }
            def publish(state, latest, runner, fields):
                report = {
                    "runner": runner, "passed": True, "result": "pass",
                    "dispatcher": {
                        "state_root": str(state),
                        "authoritative_report": str(state / "report.json"),
                        "latest_report": str(latest),
                        "source_identity": source,
                    }, **fields,
                }
                data = json.dumps(report)
                (state / "report.json").write_text(data, encoding="utf-8")
                latest.write_text(data, encoding="utf-8")
            static_report = work / "static-selected.json"
            dynamic_report = work / "dynamic-selected.json"
            publish(static, static_report, "crabc-lua-native-x86-static-source-build", {
                "environment": {"sysroot_manifest": manifest},
                "modes": {name: {"workloads": workloads} for name in ("static-et-exec", "static-pie")},
            })
            publish(dynamic, dynamic_report, "crabc-lua-native-x86-dynamic-source-build-dispatch", {
                "installed": lane, "extracted": lane,
                "reproducibility": {"status": "passed", "installed_artifacts": hashes, "extracted_artifacts": hashes},
            })
            def product(root):
                observed = json.loads((root / "share/crabc/manifest.json").read_text(encoding="utf-8"))
                return root, root / "crabc-cc", {}, observed
            with (
                mock.patch.object(ADMISSION.LUA, "current_source_identity", return_value=source),
                mock.patch.object(ADMISSION, "validate_pinned_input"),
                mock.patch.object(ADMISSION.LUA, "owned_static_sysroot", side_effect=product),
                mock.patch.object(ADMISSION.DYNAMIC, "owned_dynamic_sysroot", side_effect=product),
                mock.patch.object(ADMISSION.QUALIFICATION, "product_identity"),
            ):
                yield work, static_report, dynamic_report

    def test_nondefault_dispatcher_report_selection_replays_without_global_changes(self) -> None:
        with self.selected_reports() as (work, static, dynamic):
            receipt = ADMISSION.write_receipt(work / "admission", static_report=static, dynamic_report=dynamic)
            record = ADMISSION.validate_receipt(ROOT, receipt)
            self.assertEqual(record["schema"], ADMISSION.RECEIPT_SCHEMA)
            self.assertEqual(record["admission"]["static"]["report_sha256"], ADMISSION.LUA.sha256_file(static))
            self.assertEqual(record["admission"]["dynamic"]["report_sha256"], ADMISSION.LUA.sha256_file(dynamic))

    def test_cli_selects_and_retains_nondefault_reports_for_ordinary_replay(self) -> None:
        with self.selected_reports() as (work, static, dynamic):
            output = work / "admission"
            with contextlib.redirect_stdout(io.StringIO()):
                status = ADMISSION.main([
                    "--static-report", str(static), "--dynamic-report", str(dynamic),
                    "--output", str(output),
                ])
            self.assertEqual(status, 0)
            ADMISSION.validate_receipt(ROOT, output / "admission.json")

    def test_default_receipt_retains_its_original_admission_fields(self) -> None:
        with self.selected_reports() as (work, static, dynamic):
            with (
                mock.patch.object(ADMISSION, "STATIC_REPORT", static),
                mock.patch.object(ADMISSION, "DYNAMIC_REPORT", dynamic),
            ):
                receipt = ADMISSION.write_receipt(work / "admission")
                record = ADMISSION.validate_receipt(ROOT, receipt)
            self.assertEqual(set(record), {"schema", "gate", "admission"})
            self.assertEqual(set(record["admission"]["static"]), {"report_sha256", "product_sha256"})
            self.assertEqual(set(record["admission"]["dynamic"]), {"report_sha256", "installed", "extracted"})

    def test_nondefault_selected_report_change_invalidates_retained_admission(self) -> None:
        with self.selected_reports() as (work, static, dynamic):
            receipt = ADMISSION.write_receipt(work / "admission", static_report=static, dynamic_report=dynamic)
            report = json.loads(static.read_text(encoding="utf-8"))
            report["retained_observation"] = "changed"
            data = json.dumps(report)
            static.write_text(data, encoding="utf-8")
            (work / "static/report.json").write_text(data, encoding="utf-8")
            with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "differs from a fresh admission"):
                ADMISSION.validate_receipt(ROOT, receipt)

    def test_nondefault_selected_product_change_invalidates_retained_admission(self) -> None:
        with self.selected_reports() as (work, static, dynamic):
            receipt = ADMISSION.write_receipt(work / "admission", static_report=static, dynamic_report=dynamic)
            (work / "dynamic/extracted/share/crabc/manifest.json").write_text('{"files": {}}', encoding="utf-8")
            with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "product differ"):
                ADMISSION.validate_receipt(ROOT, receipt)

    def test_report_selection_cannot_redirect_a_dispatcher_latest_path(self) -> None:
        with self.selected_reports() as (work, static, dynamic):
            forged = work / "forged-latest.json"
            forged.write_bytes(static.read_bytes())
            with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "selected latest report"):
                ADMISSION.write_receipt(work / "admission", static_report=forged, dynamic_report=dynamic)

    def test_retained_report_locator_rejects_forged_latest_and_symlink_alias(self) -> None:
        with self.selected_reports() as (work, static, dynamic):
            receipt = ADMISSION.write_receipt(work / "admission", static_report=static, dynamic_report=dynamic)
            original = json.loads(receipt.read_text(encoding="utf-8"))
            forged = work / "forged-latest.json"
            forged.write_bytes(static.read_bytes())
            alias = work / "static-alias.json"
            alias.symlink_to(static.name)
            for selected, message in ((forged, "selected latest report"), (alias, "symlink")):
                with self.subTest(selected=selected.name):
                    record = json.loads(json.dumps(original))
                    record["admission"]["static"]["report_path"] = str(selected.relative_to(ROOT))
                    receipt.write_text(json.dumps(record), encoding="utf-8")
                    with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, message):
                        ADMISSION.validate_receipt(ROOT, receipt)

    def test_dispatcher_latest_cannot_name_a_symlink_to_selected_report(self) -> None:
        with self.selected_reports() as (work, static, dynamic):
            alias = work / "dispatcher-latest-alias.json"
            alias.symlink_to(static.name)
            report = json.loads(static.read_text(encoding="utf-8"))
            report["dispatcher"]["latest_report"] = str(alias)
            data = json.dumps(report)
            static.write_text(data, encoding="utf-8")
            (work / "static/report.json").write_text(data, encoding="utf-8")
            with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "symlink"):
                ADMISSION.write_receipt(work / "admission", static_report=static, dynamic_report=dynamic)

    def test_retained_report_locator_rejects_absolute_and_parent_paths(self) -> None:
        with self.selected_reports() as (work, static, dynamic):
            receipt = ADMISSION.write_receipt(work / "admission", static_report=static, dynamic_report=dynamic)
            original = json.loads(receipt.read_text(encoding="utf-8"))
            for locator in (str(static), "../outside.json", ".work/../outside.json", "", 17):
                with self.subTest(locator=locator):
                    record = json.loads(json.dumps(original))
                    record["admission"]["static"]["report_path"] = locator
                    receipt.write_text(json.dumps(record), encoding="utf-8")
                    with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "locator"):
                        ADMISSION.validate_receipt(ROOT, receipt)

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


    def test_retained_admission_passes_only_while_a_fresh_admission_is_identical(self) -> None:
        admitted = {
            "source_identity": {"revision": "1" * 40, "source_sha256": "1" * 64},
            "static": {"report_sha256": "2" * 64, "product_sha256": "3" * 64},
            "dynamic": {"report_sha256": "4" * 64, "installed": "5" * 64, "extracted": "5" * 64},
        }
        ADMISSION.WORK.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="receipt-", dir=ADMISSION.WORK) as temporary:
            output = Path(temporary) / "admission"
            with mock.patch.object(ADMISSION, "validate", return_value=admitted):
                receipt = ADMISSION.write_receipt(output)
                self.assertEqual(receipt, output / "admission.json")
                self.assertEqual(ADMISSION.validate_receipt(ROOT, receipt)["admission"], admitted)
                with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "not fresh"):
                    ADMISSION.write_receipt(output)

            replaced = {**admitted, "dynamic": {**admitted["dynamic"], "report_sha256": "6" * 64}}
            with mock.patch.object(ADMISSION, "validate", return_value=replaced):
                with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "differs from a fresh admission"):
                    ADMISSION.validate_receipt(ROOT, receipt)

            failure = ADMISSION.LUA.RunnerError("Lua source-build report was produced from stale source")
            with mock.patch.object(ADMISSION, "validate", side_effect=failure):
                with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "stale source"):
                    ADMISSION.validate_receipt(ROOT, receipt)
                with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "stale source"):
                    ADMISSION.write_receipt(Path(temporary) / "second")
                self.assertFalse((Path(temporary) / "second").exists())

            record = json.loads(receipt.read_text(encoding="utf-8"))
            record["gate"] = "consumer.rust-std-lto"
            receipt.write_text(json.dumps(record), encoding="utf-8")
            with mock.patch.object(ADMISSION, "validate", return_value=admitted):
                with self.assertRaisesRegex(ADMISSION.LUA.RunnerError, "schema"):
                    ADMISSION.validate_receipt(ROOT, receipt)


if __name__ == "__main__":
    unittest.main()
