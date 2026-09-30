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

    def test_artifact_parent_alias_cannot_escape_owning_checkout(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as directory:
            alias = Path(directory) / "foreign-source"
            alias.symlink_to(ROOT.parents[2], target_is_directory=True)
            record = reader.harness.artifact_record(alias / "Cargo.toml")
            with self.assertRaisesRegex(reader.harness.HarnessError, "escapes"):
                reader.authenticate_artifacts(record, Path(directory))

    def test_retained_source_selection_rejects_alias_without_loading_helpers(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as directory:
            alias = Path(directory) / "producer"
            alias.symlink_to(ROOT, target_is_directory=True)
            with self.assertRaisesRegex(reader.harness.HarnessError, "alias escapes"):
                with reader.receipt_source(alias):
                    self.fail("an alias must not load a producer helper")

    def test_compiler_integration_target_identity_is_checked_independently(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as directory:
            binary = Path(directory) / "owner-test"
            binary.write_bytes(b"compiler-selected integration fixture")
            event = {"reason": "compiler-artifact", "target": {"name": "persistent_owner", "kind": ["test"]},
                     "profile": {"test": True}, "executable": str(binary)}
            build = {"command": ["cargo", "test"], "status": 0, "stdout": json.dumps(event), "stderr": ""}
            program = {"artifact": reader.harness.artifact_record(binary), "build": build,
                       "build_command": build["command"], "cargo_target": directory}
            reader.authenticate_unit_program(program, target="persistent_owner", kind="test")
            for defect in ("target", "kind", "test-profile"):
                altered = json.loads(json.dumps(event))
                if defect == "target":
                    altered["target"]["name"] = "unrelated_test"
                elif defect == "kind":
                    altered["target"]["kind"] = ["lib"]
                else:
                    altered["profile"]["test"] = False
                program["build"]["stdout"] = json.dumps(altered)
                with self.assertRaisesRegex(reader.harness.HarnessError, "does not identify"):
                    reader.authenticate_unit_program(program, target="persistent_owner", kind="test")

    def test_replay_keeps_raw_process_evidence_in_private_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as directory:
            destination = Path(directory) / "replay"
            with mock.patch.dict(reader.os.environ, {"CRABC_RECEIPT_REPLAY_OUTPUT": str(destination)}):
                result = reader.execute([sys.executable, "-c", "print('physical replay output')"], 30,
                                        env=dict(reader.os.environ, REPLAY_MARKER="actual"))
            self.assertEqual(result["status"], 0)
            self.assertEqual(result["stdout"], "physical replay output\n")
            self.assertEqual(json.loads((destination / "command-000.json").read_text()), result)

    def test_unusable_private_output_cannot_publish_replay_success(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as directory:
            blocked = Path(directory) / "replay-output"
            blocked.write_bytes(b"retained input must remain unchanged")
            with mock.patch.dict(reader.os.environ, {"CRABC_RECEIPT_REPLAY_OUTPUT": str(blocked)}):
                with self.assertRaises(OSError):
                    reader.execute([sys.executable, "-c", "print('process completed')"], 30)
            self.assertEqual(blocked.read_bytes(), b"retained input must remain unchanged")

    def test_local_component_cli_dispatches_without_claiming_full_gate(self):
        with mock.patch.object(reader, "read_m3_components", create=True) as components:
            with mock.patch.object(sys, "argv", ["reader", "m3", "--components-only", "--report", "local.json"]):
                self.assertEqual(reader.main(), 0)
            components.assert_called_once_with(Path("local.json"))

    def test_local_component_completion_labels_require_physical_miri_inputs(self):
        import m3_x86_64 as local
        contract = local.load_contract()
        checks = {name: {"status": "passed", "unmet": []}
                  for component in contract["components"] for name in component["checks"]}
        checks["prerequisites"] = {"unmet": ["source substrate remains incomplete"]}
        report = {"source": {}, "contract_sha256": reader.harness.file_digest(local.CONTRACT_PATH),
                  "checks": checks, "gate": local.evaluate_gate(contract, checks)}
        original = reader.harness.read_json
        with mock.patch.object(reader, "authenticate_source"), mock.patch.object(reader.harness, "runtime_ticket_zero_soak_source_state", return_value={}):
            with mock.patch.object(reader.harness, "read_json", side_effect=lambda path: report if path == Path("local.json") else original(path)):
                with self.assertRaisesRegex(reader.harness.HarnessError, "Miri.*physical"):
                    reader.read_m3_components(Path("local.json"))

    def test_source_incomplete_substrate_cannot_be_saved_as_complete(self):
        report = {"milestone": {"status": "complete"}}
        original = reader.harness.read_json
        with mock.patch.object(reader.harness, "read_json", side_effect=lambda path: report if path == Path("receipt.json") else original(path)):
            with self.assertRaisesRegex(reader.harness.HarnessError, "incomplete"):
                reader.read_m2(Path("receipt.json"))


class RetainedProducerSourceTests(unittest.TestCase):
    def setUp(self):
        import subprocess
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp", prefix="retained-source-")
        self.addCleanup(self.temporary.cleanup)
        self.receiver_root = Path(self.temporary.name) / "receiver"
        self.producer_root = Path(self.temporary.name) / "producer"
        for root in (self.receiver_root, self.producer_root):
            (root / "compat/allocator").mkdir(parents=True)
            (root / "compat/x86_64").mkdir()
            (root / ".gitignore").write_text(".work/\n__pycache__/\n")
        (self.receiver_root / "compat/x86_64/native_shadow_receipt.py").write_bytes(
            (ROOT / "compat/x86_64/native_shadow_receipt.py").read_bytes())
        self.receiver_file = self.receiver_root / "compat/allocator/x86_64_foundation_gate_receipts.py"
        self.receiver_file.write_text("receiver_identity = 'original'\n")
        self.producer_file = self.producer_root / "compat/allocator/run.py"
        self.producer_file.write_text("from pathlib import Path\nROOT = Path(__file__).resolve().parents[2]\nWORK_ROOT = ROOT / '.work'\n")
        (self.producer_root / "compat/allocator/m3_x86_64.py").write_text(
            "from pathlib import Path\nROOT = Path(__file__).resolve().parents[2]\n")
        for root in (self.receiver_root, self.producer_root):
            for argv in (["git", "init", "-q"], ["git", "add", "."],
                         ["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "source"]):
                subprocess.run(argv, cwd=root, check=True, capture_output=True)

    def test_selected_helpers_keep_original_root_and_restore_receiver_modules(self):
        original = reader.harness
        original_run = sys.modules["run"]
        original_path = list(sys.path)
        original_bytecode = sys.dont_write_bytecode
        with mock.patch.object(reader, "__file__", str(self.receiver_file)):
            with reader.receipt_source(self.producer_root) as identities:
                self.assertEqual(reader.harness.ROOT, self.producer_root)
                self.assertIs(sys.modules["run"], reader.harness)
                self.assertNotEqual(identities[0]["revision"], identities[1]["revision"])
        self.assertIs(reader.harness, original)
        self.assertIs(sys.modules["run"], original_run)
        self.assertEqual(sys.path, original_path)
        self.assertEqual(sys.dont_write_bytecode, original_bytecode)
        self.assertEqual(list(self.producer_root.rglob("__pycache__")), [])
        self.assertEqual(list(self.receiver_root.rglob("__pycache__")), [])

    def test_untracked_bytecode_cannot_replace_committed_producer_helper(self):
        import os
        import py_compile
        original = self.producer_file.read_bytes()
        stamp = self.producer_file.stat()
        forged = b"raise RuntimeError('forged bytecode executed')\n"
        self.producer_file.write_bytes(forged + b" " * (len(original) - len(forged)))
        os.utime(self.producer_file, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        py_compile.compile(str(self.producer_file), doraise=True)
        self.producer_file.write_bytes(original)
        os.utime(self.producer_file, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        with mock.patch.object(reader, "__file__", str(self.receiver_file)):
            with reader.receipt_source(self.producer_root):
                self.assertEqual(reader.harness.ROOT, self.producer_root)

    def test_dirty_producer_is_refused_before_helper_loading(self):
        self.producer_file.write_text(self.producer_file.read_text() + "modified = True\n")
        original = reader.harness
        with mock.patch.object(reader, "__file__", str(self.receiver_file)):
            with self.assertRaisesRegex(reader.harness.HarnessError, "producer source is not clean"):
                with reader.receipt_source(self.producer_root):
                    self.fail("dirty producer was loaded")
        self.assertIs(reader.harness, original)

    def test_changed_receiver_or_producer_during_replay_cannot_reuse_original_seal(self):
        original = reader.harness
        for changed, message in ((self.receiver_file, "receiver source changed"),
                                 (self.producer_file, "producer source changed")):
            with self.subTest(changed=changed):
                contents = changed.read_bytes()
                with mock.patch.object(reader, "__file__", str(self.receiver_file)):
                    with self.assertRaisesRegex(reader.harness.HarnessError, message):
                        with reader.receipt_source(self.producer_root):
                            changed.write_bytes(contents + b"changed = True\n")
                self.assertIs(reader.harness, original)
                changed.write_bytes(contents)


class MiriPhysicalReaderTests(unittest.TestCase):
    def setUp(self):
        import m3_x86_64 as local
        from compat.allocator.tests.test_x86_64_m3_local_engine import MiriFreshInterpreterDispatchTests
        self.local = local
        self.producer = MiriFreshInterpreterDispatchTests()
        self.producer.setUp()
        self.addCleanup(self.producer.doCleanups)
        cargo = self.producer.fixture / "bin/cargo"
        cargo.write_text(cargo.read_text().replace("0 measured; 0 filtered out", "0 measured; 0 filtered out; finished in 0.00s"))
        self.miri, _calls = self.producer.execute()
        self.contract = local.load_contract()
        self.contract["miri"] = self.producer.contract["miri"]
        self.authority = {key: self.miri["physical_inputs"][key] for key in (
            "program", "dep_info", "source_files", "dependencies", "dependency_info",
            "search_directories", "sysroot", "tools", "phase_environment")}
        self.authority["tools"]["cargo-miri"]["version"]["stdout"] = self.miri["physical_inputs"]["probe"]["stdout"]
        channel = reader.tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        for name, tool in self.authority["tools"].items():
            tool["executable_path"] = f"/opt/rustup/toolchains/{channel}-x86_64-unknown-linux-musl/bin/{name}"
        checks = {name: {"status": "passed", "unmet": []}
                  for component in self.contract["components"] for name in component["checks"]}
        checks["miri"] = self.miri
        checks["prerequisites"] = {"unmet": ["memory substrate remains incomplete"]}
        self.report = {"source": {}, "checks": checks,
                       "contract_sha256": reader.harness.file_digest(local.CONTRACT_PATH),
                       "gate": local.evaluate_gate(self.contract, checks)}

    def read(self, replay=None):
        original = reader.harness.read_json
        with mock.patch.object(self.local, "load_contract", return_value=self.contract), \
             mock.patch.object(self.local, "_miri_compiler_inputs", return_value=self.authority), \
             mock.patch.object(reader, "authenticate_source"), \
             mock.patch.object(reader.harness, "runtime_ticket_zero_soak_source_state", return_value={}), \
             mock.patch.object(reader.harness, "read_json", side_effect=lambda path: self.report if path == Path("local.json") else original(path)), \
             mock.patch.object(reader, "execute", side_effect=replay) as execute:
            try:
                return reader.read_m3_components(Path("local.json"))
            finally:
                self.executions = execute.call_args_list

    def test_changed_source_or_sysroot_bytes_are_rejected_before_replay(self):
        for key in ("program", "dep_info"):
            with self.subTest(key=key):
                record = self.miri["physical_inputs"][key]
                path = ROOT / record["path"]
                original = path.read_bytes()
                path.write_bytes(original + b"physical tamper")
                with self.assertRaisesRegex(reader.harness.HarnessError, "artifact changed"):
                    self.read()
                self.assertEqual(self.executions, [])
                path.write_bytes(original)
        sysroot = ROOT / self.authority["sysroot"]["files"][0]["path"]
        sysroot.write_bytes(b"substituted sysroot library")
        with self.assertRaisesRegex(reader.harness.HarnessError, "artifact changed"):
            self.read()
        self.assertEqual(self.executions, [])

    def test_strict_flags_and_exact_child_commands_cannot_be_weakened(self):
        physical = self.miri["physical_inputs"]
        for defect in ("flags", "child", "command", "outcome"):
            with self.subTest(defect=defect):
                original = json.loads(json.dumps(self.miri))
                row = physical["commands"]["fixture::"][0]
                if defect == "flags":
                    physical["listing"]["environment"]["MIRIFLAGS"] = "-Zmiri-disable-isolation"
                elif defect == "child":
                    row["environment"][self.local.FRESH_TEST_CHILD_ENV] = "fixture::unrelated"
                elif defect == "command":
                    row["command"].remove("--exact")
                else:
                    row["stdout"] = row["stdout"].replace("fixture::first ... ok", "fixture::unrelated ... ok")
                with self.assertRaises(reader.harness.HarnessError):
                    self.read()
                self.assertEqual(self.executions, [])
                self.miri.clear()
                self.miri.update(original)
                physical = self.miri["physical_inputs"]

    def test_private_runner_copy_changes_only_compiler_output_paths(self):
        original = json.loads((ROOT / self.authority["program"]["path"]).read_text())
        observed = []
        def replay(command, timeout, **options):
            private = json.loads(Path(command[2]).read_text())
            args = list(original["args"])
            out = args.index("--out-dir") + 1
            incremental = next(index + 1 for index, value in enumerate(args[:-1])
                               if value == "-C" and args[index + 1].startswith("incremental="))
            args[out] = private["args"][out]
            args[incremental] = private["args"][incremental]
            self.assertEqual(private, {**original, "args": args})
            self.assertTrue(Path(args[out]).is_dir())
            self.assertNotEqual(args[out], original["args"][out])
            self.assertNotEqual(args[incremental], original["args"][incremental])
            self.assertEqual(command[:2], [self.authority["tools"]["cargo-miri"]["executable_path"], "runner"])
            self.assertEqual(options["env"]["MIRI_BE_RUSTC"], "host")
            self.assertEqual(options["env"]["MIRIFLAGS"], "-Zmiri-strict-provenance -Zmiri-env-forward=CRABC_MIMALLOC_FRESH_TEST_CHILD")
            observed.append(command)
            if "--list" in command:
                self.assertNotIn(self.local.FRESH_TEST_CHILD_ENV, options["env"])
                return self.miri["physical_inputs"]["listing"]
            name = command[-1]
            self.assertEqual(options["env"][self.local.FRESH_TEST_CHILD_ENV], name)
            return next(row for row in self.miri["physical_inputs"]["commands"]["fixture::"] if row["command"][-1] == name)
        with self.assertRaises(KeyError):
            self.read(replay)
        self.assertEqual(len(observed), 3)
        self.assertEqual(json.loads((ROOT / self.authority["program"]["path"]).read_text()), original)

    def test_wrong_pinned_tool_directory_is_rejected_before_interpretation(self):
        self.authority["tools"]["miri"]["executable_path"] = "/ambient/bin/miri"
        with self.assertRaisesRegex(reader.harness.HarnessError, "pinned source toolchain"):
            self.read()
        self.assertEqual(self.executions, [])


if __name__ == "__main__":
    unittest.main()
