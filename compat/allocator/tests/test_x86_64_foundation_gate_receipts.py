"""Behavioral controls for original aggregate receipt authentication."""
import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "compat/allocator"))
import x86_64_foundation_gate_receipts as reader


class FoundationReceiptTests(unittest.TestCase):
    def test_declared_artifact_bytes_are_reread_and_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as directory:
            path = Path(directory) / "program"
            path.write_bytes(b"original physical program")
            record = reader.harness.artifact_record(path)
            self.assertEqual(reader.authenticate_artifacts({"artifact": record}, Path(directory)), 1)
            path.write_bytes(b"changed physical program")
            with self.assertRaisesRegex(reader.harness.HarnessError, "artifact changed"):
                reader.authenticate_artifacts({"artifact": record}, Path(directory))
            path.unlink()
            with self.assertRaises(reader.harness.HarnessError):
                reader.authenticate_artifacts({"artifact": record}, Path(directory))

    def test_missing_focused_checks_cannot_be_replaced_by_complete_component_labels(self):
        summary = {"components": [{"id": "geometry", "native_status": reader.harness.M1_X86_64_FOUNDATIONS_COMPONENT_STATUS,
                                   "remaining_conditions": [], "checks": [{"id": "allocation", "target": "tests::allocation",
                                                                    "expected_passed_test_count": 1}]}]}
        report = {"components": [{"id": "geometry", "status": "complete", "remaining_conditions": [],
                                  "executed_checks": []}]}
        with self.assertRaisesRegex(reader.harness.HarnessError, "required focused check"):
            reader.focused_commands(report, summary)

    def test_saved_completion_cannot_close_a_source_component_condition(self):
        declaration = {"id": "allocation", "target": "tests::allocation", "expected_passed_test_count": 1}
        summary = {"components": [{"id": "geometry", "native_status": "partial",
                                   "remaining_conditions": ["unproved source branch"], "checks": [declaration]}]}
        report = {"components": [{"id": "geometry", "status": "complete", "remaining_conditions": [],
                                  "executed_checks": [{"id": "allocation", "component": "geometry",
                                      "target": "tests::allocation", "passed_test_count": 1,
                                      "command": [str(ROOT / ".work/unit-program"), "tests::allocation", "--exact"]}]}]}
        with self.assertRaisesRegex(reader.harness.HarnessError, "source component"):
            reader.focused_commands(report, summary)

    def test_wrong_source_is_refused_before_any_native_replay(self):
        with mock.patch.object(reader.harness, "require_native_x86_64") as native:
            with self.assertRaisesRegex(reader.harness.HarnessError, "current clean source"):
                reader.authenticate_source({"source": {"revision": "old"}}, {"revision": "current"},
                                           lambda before, after: before)
            native.assert_not_called()

    def test_compiler_product_identity_cannot_be_replaced_or_repointed(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as directory:
            binary = Path(directory) / "crabc_mimalloc-1234"
            binary.write_bytes(b"compiler-produced test ELF fixture")
            event = {"reason": "compiler-artifact", "target": {"name": "crabc_mimalloc", "kind": ["lib"]},
                     "profile": {"test": True}, "executable": str(binary)}
            execution = {"package": "crabc-mimalloc", "no_default_features": True,
                         "rust_target": "x86_64-unknown-linux-musl", "timeout_seconds": 300}
            def compiler(command, **arguments):
                return {"command": list(command), "status": 0, "stdout": json.dumps(event), "stderr": ""}
            with mock.patch.object(reader.harness, "command_record", side_effect=compiler):
                program = reader.harness._m1_foundations_test_program(execution, Path(directory))
            reader.authenticate_unit_program(program)
            binary.write_bytes(b"substituted unrelated executable")
            with self.assertRaisesRegex(reader.harness.HarnessError, "artifact changed"):
                reader.authenticate_unit_program(program)
            event["executable"] = str(Path(directory) / "other")
            program["build"]["stdout"] = json.dumps(event)
            with self.assertRaisesRegex(reader.harness.HarnessError, "does not identify"):
                reader.authenticate_unit_program(program)

    def test_local_engine_prerequisite_cannot_be_forged_by_a_saved_complete_label(self):
        with mock.patch.object(reader.harness, "read_json", wraps=reader.harness.read_json) as read:
            with self.assertRaisesRegex(reader.harness.HarnessError, "incomplete"):
                reader.read_m3(Path("forged-local-engine.json"))
            self.assertNotIn(mock.call(Path("forged-local-engine.json")), read.call_args_list)

    def test_source_incomplete_substrate_cannot_be_saved_as_complete(self):
        report = {"milestone": {"status": "complete"}}
        original = reader.harness.read_json
        with mock.patch.object(reader.harness, "read_json", side_effect=lambda path: report if path == Path("receipt.json") else original(path)):
            with self.assertRaisesRegex(reader.harness.HarnessError, "incomplete"):
                reader.read_m2(Path("receipt.json"))


if __name__ == "__main__":
    unittest.main()
