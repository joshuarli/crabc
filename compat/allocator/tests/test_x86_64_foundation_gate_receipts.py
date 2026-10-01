"""Behavioral controls for original aggregate receipt authentication."""
import sys
import importlib.util
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

    def test_cold_and_cached_compilers_authenticate_the_same_physical_unit_product(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as directory:
            binary = Path(directory) / "crabc_mimalloc-1234"
            binary.write_bytes(b"same compiler-selected physical test program")
            command = ["cargo", "test", "--locked", "--target", "x86_64-unknown-linux-musl",
                       "-p", "crabc-mimalloc", "--lib", "--no-default-features",
                       "--no-run", "--message-format=json"]
            selected = {"reason": "compiler-artifact", "target": {"name": "crabc_mimalloc", "kind": ["lib"]},
                        "profile": {"test": True}, "executable": str(binary)}
            dependency = {"reason": "compiler-artifact", "target": {"name": "dependency", "kind": ["lib"]},
                          "profile": {"test": False}, "executable": None}
            artifact = reader.harness.artifact_record(binary)
            programs = []
            for fresh, events, stderr in (
                    (False, [dependency, selected], "Compiling dependency\nFinished test profile in 4m 18s\n"),
                    (True, [selected, dependency], "Finished test profile in 0.30s\n")):
                build = {"command": command, "status": 0,
                         "stdout": "\n".join(json.dumps({**event, "fresh": fresh}) for event in events),
                         "stderr": stderr}
                programs.append({"artifact": artifact, "build": build, "build_command": command,
                                 "cargo_target": directory})
            self.assertNotEqual(programs[0]["build"], programs[1]["build"])
            for program in programs:
                reader.authenticate_unit_program(program, expected_product=programs[1])
            for defect in ("missing-json", "duplicate-json", "wrong-target", "wrong-profile",
                           "failed-build", "wrong-command", "other-product", "changed-product"):
                with self.subTest(defect=defect):
                    program = json.loads(json.dumps(programs[0]))
                    if defect == "missing-json":
                        program["build"]["stdout"] = json.dumps(dependency)
                    elif defect == "duplicate-json":
                        program["build"]["stdout"] += "\n" + json.dumps(selected)
                    elif defect in ("wrong-target", "wrong-profile"):
                        event = json.loads(json.dumps(selected))
                        if defect == "wrong-target":
                            event["target"]["name"] = "other"
                        else:
                            event["profile"]["test"] = False
                        program["build"]["stdout"] = json.dumps(event)
                    elif defect == "failed-build":
                        program["build"]["status"] = 1
                    elif defect == "wrong-command":
                        program["build_command"].append("--features=unselected")
                        program["build"]["command"] = program["build_command"]
                    elif defect == "other-product":
                        other = Path(directory) / "other-test"
                        other.write_bytes(binary.read_bytes())
                        program["artifact"] = reader.harness.artifact_record(other)
                        program["build"]["stdout"] = json.dumps({**selected, "executable": str(other)})
                    else:
                        binary.write_bytes(b"changed selected test program")
                    with self.assertRaises(reader.harness.HarnessError):
                        reader.authenticate_unit_program(program, expected_product=programs[1])
                    binary.write_bytes(b"same compiler-selected physical test program")

    def test_local_engine_prerequisite_cannot_be_forged_by_a_saved_complete_label(self):
        with mock.patch.object(reader.harness, "read_json", wraps=reader.harness.read_json) as read:
            with self.assertRaisesRegex(reader.harness.HarnessError, "incomplete"):
                reader.read_m3(Path("forged-local-engine.json"))
            self.assertNotIn(mock.call(Path("forged-local-engine.json")), read.call_args_list)

    def test_artifact_parent_alias_cannot_escape_owning_checkout(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as directory:
            alias = Path(directory) / "foreign-source"
            alias.symlink_to("/etc", target_is_directory=True)
            record = reader.harness.artifact_record(alias / "hostname")
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

    def test_native_only_cli_requires_bounded_local_component_mode(self):
        for arguments in (("m3",), ("m1", "--components-only"), ("m2", "--components-only")):
            with self.subTest(arguments=arguments), mock.patch.object(reader, "read_m3_components") as components, \
                 mock.patch.object(reader, "read_report") as full, mock.patch("builtins.print"):
                with mock.patch.object(sys, "argv", ["reader", *arguments, "--native-only"]):
                    self.assertEqual(reader.main(), 1)
                components.assert_not_called()
                full.assert_not_called()
        with mock.patch.object(reader, "read_m3_components", return_value={
                "scope": "native-only-diagnostic", "miri_replayed": False}) as components, \
             mock.patch("builtins.print") as printed:
            with mock.patch.object(sys, "argv", ["reader", "m3", "--components-only", "--native-only"]):
                self.assertEqual(reader.main(), 0)
            components.assert_called_once_with(None, source_root=None, native_only=True)
            printed.assert_called_once_with("retained native boundaries replay passed; Miri replay not performed")

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

    def test_output_publication_cannot_dirty_receiver_after_final_source_check(self):
        output = self.receiver_root / "compat"
        with mock.patch.object(reader, "__file__", str(self.receiver_file)),              mock.patch.dict(reader.os.environ, {"CRABC_RECEIPT_REPLAY_OUTPUT": str(output)}):
            with self.assertRaisesRegex(reader.RECEIPT_ERROR, "receiver source changed"):
                with reader.receipt_source(self.producer_root):
                    pass

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
        spec = importlib.util.spec_from_file_location(
            "miri_producer_test_fixture", Path(__file__).with_name("test_x86_64_m3_local_engine.py"))
        assert spec is not None and spec.loader is not None
        fixtures = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixtures)
        self.local = local
        self.producer = fixtures.MiriFreshInterpreterDispatchTests()
        self.producer.setUp()
        self.addCleanup(self.producer.doCleanups)
        cargo = self.producer.fixture / "bin/cargo"
        cargo.write_text(cargo.read_text().replace("0 measured; 0 filtered out", "0 measured; 0 filtered out; finished in 0.00s"))
        self.miri, _calls = self.producer.execute()
        self.contract = local.load_contract()
        self.contract["miri"] = self.producer.contract["miri"]
        self.producer.contract["miri_ownership"] = {**self.producer.contract["miri"],
            "module_prefixes": ["fixture::second"], "required_tests": ["fixture::second"]}
        self.contract["miri_ownership"] = self.producer.contract["miri_ownership"]
        self.ownership, _calls = self.producer.execute(ownership_only=True)
        self.authority = {key: self.miri["physical_inputs"][key] for key in (
            "program", "dep_info", "source_files", "dependencies", "dependency_info",
            "search_directories", "sysroot", "tools", "phase_environment")}
        self.authority["tools"]["cargo-miri"]["version"]["stdout"] = self.miri["physical_inputs"]["probe"]["stdout"]
        channel = reader.tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        for name, tool in self.authority["tools"].items():
            tool["executable_path"] = f"/opt/rustup/toolchains/{channel}-x86_64-unknown-linux-musl/bin/{name}"
        guarded_program = self.producer.program.with_name("guarded-compiler")
        metadata = json.loads(self.producer.program.read_text())
        metadata["args"].extend(["--cfg", 'feature="mi-guarded"'])
        guarded_program.write_text(json.dumps(metadata))
        guarded_program.with_suffix(".d").write_bytes(self.producer.program.with_suffix(".d").read_bytes())
        self.producer.contract["miri_guarded_ownership"] = {**self.contract["miri_ownership"], "features": ["mi-guarded"]}
        self.contract["miri_guarded_ownership"] = self.producer.contract["miri_guarded_ownership"]
        with mock.patch.dict(self.producer.environment, {"MIRI_TEST_PROGRAM": str(guarded_program)}):
            self.guarded, _calls = self.producer.execute(profile=local.MiriProfile.GUARDED_OWNERSHIP)
        self.guarded_authority = {key: self.guarded["physical_inputs"][key] for key in self.authority}
        self.guarded_authority["tools"] = self.authority["tools"]
        self.guarded["physical_inputs"].update(self.guarded_authority)
        checks = {name: {"status": "passed", "unmet": []}
                  for component in self.contract["components"] for name in component["checks"]}
        self.ownership["physical_inputs"].update(self.authority)
        checks["miri"] = self.miri
        checks["miri-ownership"] = self.ownership
        checks["miri-guarded-ownership"] = self.guarded
        checks["prerequisites"] = {"unmet": ["memory substrate remains incomplete"]}
        self.report = {"source": {}, "checks": checks,
                       "contract_sha256": reader.harness.file_digest(local.CONTRACT_PATH),
                       "gate": local.evaluate_gate(self.contract, checks)}
        self.prepare_native_inputs()

    def prepare_native_inputs(self):
        h, local = reader.harness, self.local
        self.artifacts = self.producer.fixture / "native-artifacts"
        self.artifacts.mkdir()
        self.pin = h.load_pin()
        self.oracle = self.artifacts / "source" / self.pin["archive_root"]
        (self.oracle / "include").mkdir(parents=True)
        (self.oracle / "src").mkdir()
        self.c_binary = self.artifacts / "c-program"
        self.c_binary.write_bytes(b"native fixture C compiler product")
        target = self.producer.fixture / "target"
        target.mkdir()
        self.unit_binary = target / "unit-program"
        self.owner_binary = target / "owner-program"
        for binary in (self.unit_binary, self.owner_binary):
            binary.write_bytes(b"native fixture Rust compiler product")
        command = ["cargo", "test", "--locked", "--target", local.TARGET, "-p", "crabc-mimalloc",
                   "--lib", "--no-default-features", "--no-run", "--message-format=json"]
        unit = {"artifact": h.artifact_record(self.unit_binary), "build_command": command,
                "build": {"command": command, "status": 0, "stdout": json.dumps({
                    "reason": "compiler-artifact", "target": {"name": "crabc_mimalloc", "kind": ["lib"]},
                    "profile": {"test": True}, "executable": str(self.unit_binary)}), "stderr": ""}}
        self.native_listing = {"command": [str(self.unit_binary), "--list", "--format", "terse"],
                               "status": 0, "stdout": local.RUST_TRACE_TEST + ": test\n", "stderr": ""}
        execution = {"command": [str(self.unit_binary), "--exact", "--test-threads=1", local.RUST_TRACE_TEST],
                     "status": 0, "stdout": "test " + local.RUST_TRACE_TEST + " ... ok\n\n"
                     "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
                     "stderr": ""}
        self.contract["rust_unit_batch"]["module_prefixes"] = [local.RUST_TRACE_TEST]
        unit_check = self.report["checks"]["rust-unit-batch"]
        unit_check.update({"binary": str(self.unit_binary), "passed": 1,
                          "groups": {local.RUST_TRACE_TEST: local.summarize_group(local.RUST_TRACE_TEST,
                                      [local.RUST_TRACE_TEST], execution)},
                          "physical_inputs": {"build": unit, "binary": unit["artifact"],
                              "listing": self.native_listing, "commands": {local.RUST_TRACE_TEST: execution}}})
        self.native_execution = execution
        specification = next(row for row in self.contract["workloads"] if row["generator"] == "queue-candidate-front")
        self.contract["workloads"] = [specification]
        size, freed = (int(specification["parameters"][key]) for key in ("size", "freed_from_first"))
        capacity = local.page_size_for_block(size) // size
        bin_index = local.source_bin(size)
        before, move = capacity + 1 + freed, capacity + 2 + freed
        self.c_lines = ["@1 a", "= P1", f"@{capacity + 1} a", "= P2",
                        f"Q{bin_index} 2 n1", f"Q{local.BIN_FULL} 1 n1",
                        f"+P2 q{bin_index} s{size} c1 r{capacity} u1 f- l- x0 F0 z0 S0",
                        f"@{before} f", f"Q{bin_index} 2,1 n2",
                        f"+P1 q{bin_index} s{size} c{capacity} r{capacity} u{capacity - freed} f- l1 x0 F0 z0 S0",
                        f"@{move} a", "= P1", f"Q{bin_index} 1,2 n2"]
        self.c_lines.extend(f"D{index} P1" for index in range(1, local.SMALL_SIZE_MAX // local.WORD + 1))
        self.contract["coverage_requirements"] = {"regular_bin_events": [], "huge_bin_events": [],
            "retired_reuse_classes": [], "minimum_admin_mini_collections": 0, "minimum_admin_full_collections": 0}
        coverage = local.trace_coverage(self.c_lines)
        workload_name, workload_text = next(iter(local.generate_workloads(self.contract).items()))
        workload = self.artifacts / "workload"
        workload.write_text(workload_text)
        trace = self.artifacts / "trace"
        trace.write_text("\n".join(self.c_lines) + "\n")
        row = {"id": workload_name, "status": "matched", "divergence": None, "c_repeat_identical": True,
               "trace_lines": len(self.c_lines), "coverage": coverage,
               "workload_sha256": local.sha256_bytes(workload_text.encode()),
               "c_trace_sha256": h.sha256_file(trace), "rust_trace_sha256": h.sha256_file(trace),
               "queue_candidate_front": json.loads(json.dumps(local.queue_candidate_front_witness(self.c_lines, size, freed))),
               "physical_inputs": {"workload": h.artifact_record(workload),
                   **{name: h.artifact_record(trace) for name in ("c_trace", "c_repeat", "rust_trace")}}}
        self.witness_row = row
        driver = self.contract["persistent_owner_profile"]["rust_driver"]
        owner_command = ["cargo", "test", "--locked", "--target", local.TARGET, "-p", "crabc-mimalloc",
                         "--no-default-features", "--features", ",".join(driver["features"]), "--test", driver["target"],
                         "--no-run", "--message-format=json"]
        owner = {"artifact": h.artifact_record(self.owner_binary), "build_command": owner_command,
                 "build": {"command": owner_command, "status": 0, "stdout": json.dumps({
                     "reason": "compiler-artifact", "target": {"name": driver["target"], "kind": ["test"]},
                     "profile": {"test": True}, "executable": str(self.owner_binary)}), "stderr": ""}}
        self.contract["persistent_owner_profile"]["coverage_requirements"] = {
            "page_classes": [], "page_class_events": [], "forbidden_events": [], "minimum_admin_mini_collections": 0}
        owner_workload = self.artifacts / "owner-workload"
        owner_workload.write_text("fixture owner workload\n")
        self.owner_workloads = {"fixture-owner": owner_workload.read_text()}
        owner_rows = [{**row, "id": "fixture-owner", "owner": identity,
                       "workload_sha256": local.sha256_bytes(owner_workload.read_bytes()),
                       "physical_inputs": {**row["physical_inputs"], "workload": h.artifact_record(owner_workload)}}
                      for identity in self.contract["persistent_owner_profile"]["owners"]]
        for owner_row in owner_rows:
            del owner_row["queue_candidate_front"]
        for name, program, rows in (("local-trace-differential", unit, [row]),
                                     ("persistent-owner-trace-differential", owner, owner_rows)):
            check = self.report["checks"][name]
            check.update({"archive_sha256": self.pin["sha256"], "c_driver_sha256": h.sha256_file(local.C_DRIVER_PATH),
                "rust_driver_sha256": h.sha256_file(local.OWNER_RUST_DRIVER_PATH if name == "persistent-owner-trace-differential" else local.RUST_DRIVER_PATH),
                "workloads": rows, "coverage_unmet": [], "coverage": local.merge_coverage([coverage]) if name == "local-trace-differential" else {
                    owner: local.merge_coverage([coverage]) for owner in self.contract["persistent_owner_profile"]["owners"]},
                "trace_audit_sha256": h.sha256_file(local.OWNER_TRACE_AUDIT_PATH),
                "physical_inputs": {"artifact": h.artifact_record(self.c_binary), "source_files": [], "rust_program": program,
                    "build": {"command": local.c_driver_command("musl-gcc", self.oracle, self.c_binary, self.contract),
                              "status": 0, "stdout": "", "stderr": ""}}})
        self.reorder_lines = [f"M3Q {step} regular={regular} full={full} bytes={sum({'A':128,'B':192,'C':256}[p] for p in full)} pages=3"
            for step, regular, full in (("start", "ABC", ""), ("first-full", "BC", "A"), ("middle-full", "C", "AB"),
                                       ("full-front", "C", "BA"), ("second-position", "CB", "A"), ("full-return", "CBA", ""))]
        fixture = self.contract["queue_reorder_differential"]
        runtime = {"physical_inputs": {"c_program": h.artifact_record(self.c_binary), "rust_program": unit["artifact"]},
            **{key: h.sha256_file(ROOT / fixture[key.removesuffix("_sha256")]) for key in ("c_fixture_sha256", "runner_sha256")},
            "rust_source_sha256": h.sha256_file(ROOT / "crabc-mimalloc/src/page_queue.rs"),
            "archive_sha256": self.pin["sha256"], "rust_test": fixture["rust_test"],
            "c_build": {"command": ["musl-gcc", "-std=c11", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1", *h.CONFIGURATION_PROFILES["release"],
                "-I", str(self.oracle / "include"), "-I", str(self.oracle / "src"), str(ROOT / fixture["c_fixture"]), "-o", str(self.c_binary)], "status": 0},
            "c_runtime": {"command": [str(self.c_binary)], "status": 0, "stdout": "\n".join(self.reorder_lines)},
            "rust_runtime": {"command": [str(self.unit_binary), fixture["rust_test"], "--exact", "--nocapture", "--test-threads=1"],
                "status": 0, "stdout": "\n".join(self.reorder_lines) + "\n" + execution["stdout"], "stderr": ""}}
        receipt = self.artifacts / "reorder.json"
        h.write_json(receipt, runtime)
        self.report["checks"]["queue-reorder-differential"].update({**runtime, "raw_runtime_receipt": str(receipt),
            "physical_inputs": {**runtime["physical_inputs"], "receipt": h.artifact_record(receipt)}})
        retirement = self.report["checks"]["queue-retirement-differential"]
        fixture = self.contract["queue_retirement_differential"]
        h.write_json(self.artifacts / "queue-retirement-driver.json", {})
        for filename in ("queue-retirement.c.trace", "queue-retirement.rust.trace", "queue-retirement.trace"):
            (self.artifacts / filename).write_text("retained queue fixture trace\n")
        retirement.update({"raw_driver_receipt": str(self.artifacts / "queue-retirement-driver.json"),
            **{key: h.sha256_file(ROOT / fixture[key.removesuffix("_sha256")]) for key in ("c_fixture_sha256", "runner_sha256")},
            "rust_source_sha256": h.sha256_file(ROOT / "crabc-mimalloc/src/page_queue.rs"),
            "rust_free_list_sha256": h.sha256_file(ROOT / "crabc-mimalloc/src/free_list.rs"),
            **{key: fixture[key] for key in ("rust_test", "rust_matrix_test", "rust_free_test")},
            **{key: h.sha256_file(self.artifacts / filename) for key, filename in (
                ("c_trace_sha256", "queue-retirement.c.trace"), ("rust_trace_sha256", "queue-retirement.rust.trace"),
                ("trace_sha256", "queue-retirement.trace"))}})

    def replay_native(self, command, timeout, **options):
        if "-o" in command:
            Path(command[command.index("-o") + 1]).write_bytes(self.c_binary.read_bytes())
            return {"command": command, "status": 0, "stdout": "", "stderr": ""}
        if "--list" in command:
            return self.native_listing
        if command == [str(self.c_binary)]:
            return {"command": command, "status": 0, "stdout": "\n".join(self.reorder_lines), "stderr": ""}
        if command[0] == str(self.c_binary):
            Path(command[2]).write_text("\n".join(self.c_lines) + "\n")
        for key in (self.local.OUTPUT_ENV, self.local.OWNER_OUTPUT_ENV):
            if key in options.get("env", {}):
                Path(options["env"][key]).write_text("\n".join(self.c_lines) + "\n")
        return {**self.native_execution, "command": command,
                "stdout": "\n".join(self.reorder_lines) + "\n" + self.native_execution["stdout"]}

    def read(self, replay=None, *, native_only=False):
        original = reader.harness.read_json
        import x86_64_m3_queue_retirement as queue
        def dispatch(command, timeout, **options):
            if command[0] == self.authority["tools"]["cargo-miri"]["executable_path"]:
                return replay(command, timeout, **options)
            return self.replay_native(command, timeout, **options)
        with mock.patch.object(queue, "read_report", return_value={}), \
             mock.patch.object(reader.harness, "WORK_ROOT", self.producer.fixture), \
             mock.patch.object(self.local, "ARTIFACT_ROOT", self.artifacts), \
             mock.patch.object(reader.harness, "fetch_archive", return_value=self.artifacts / "archive"), \
             mock.patch.object(reader.harness, "safe_extract", return_value=self.oracle), \
             mock.patch.object(reader.harness, "source_file_records", return_value=[]), \
             mock.patch.object(reader.harness, "require_tool", return_value="musl-gcc"), \
             mock.patch.object(self.local, "generate_owner_workloads", return_value=self.owner_workloads), \
             mock.patch.object(self.local, "load_contract", return_value=self.contract), \
             mock.patch.object(self.local, "_miri_compiler_inputs", side_effect=lambda listing, selected: self.guarded_authority if selected.get("features") else self.authority), \
             mock.patch.object(reader, "authenticate_source"), \
             mock.patch.object(reader.harness, "runtime_ticket_zero_soak_source_state", return_value={}), \
             mock.patch.object(reader.harness, "TEMP_ROOT", self.producer.fixture / "reader-scratch"), \
             mock.patch.object(reader.harness, "read_json", side_effect=lambda path: self.report if path == Path("local.json") else original(path)), \
             mock.patch.object(reader, "execute", side_effect=dispatch) as execute:
            try:
                return reader.read_m3_components(Path("local.json"), native_only=native_only)
            finally:
                self.executions = execute.call_args_list

    def test_queue_witness_json_roundtrip_and_native_only_scope(self):
        result = self.read(native_only=True)
        self.assertEqual(result, {"scope": "native-only-diagnostic", "miri_replayed": False})
        self.assertTrue(self.executions)
        self.assertFalse(any(call.args[0][0] == self.authority["tools"]["cargo-miri"]["executable_path"]
                             for call in self.executions))
        original = json.loads(json.dumps(self.witness_row["queue_candidate_front"]))
        for defect in ("wrong-value", "missing", "extra", "wrong-type", "boolean", "float"):
            with self.subTest(defect=defect):
                witness = json.loads(json.dumps(original))
                if defect == "wrong-value":
                    witness["selected_page"] += 1
                elif defect == "missing":
                    del witness["first_before_move"]
                elif defect == "extra":
                    witness["invented"] = 1
                elif defect == "boolean":
                    witness["selected_page"] = True
                elif defect == "float":
                    witness["selected_page"] = float(witness["selected_page"])
                else:
                    witness["selected_page"] = str(witness["selected_page"])
                self.witness_row["queue_candidate_front"] = witness
                with self.assertRaisesRegex(reader.harness.HarnessError, "queue candidate witness changed"):
                    self.read(native_only=True)
        self.witness_row["queue_candidate_front"] = original

    def test_ownership_semantics_are_authenticated_before_native_only_replay(self):
        for defect in ("program", "roster", "flags", "log"):
            with self.subTest(defect=defect):
                original = json.loads(json.dumps(self.ownership))
                physical = self.ownership["physical_inputs"]
                log = ROOT / physical["log"]["path"]
                original_log = log.read_bytes()
                if defect == "program":
                    physical["program"] = physical["dep_info"]
                elif defect == "roster":
                    physical["commands"].clear()
                elif defect == "flags":
                    physical["listing"]["environment"]["MIRIFLAGS"] = "-Zmiri-disable-isolation"
                else:
                    log.write_bytes(original_log + b"invented observation\n")
                    physical["log"] = reader.harness.artifact_record(log)
                try:
                    with self.assertRaises(reader.harness.HarnessError):
                        self.read(native_only=True)
                    self.assertEqual(self.executions, [])
                finally:
                    log.write_bytes(original_log)
                    self.ownership.clear()
                    self.ownership.update(original)

    def test_guarded_profile_cannot_substitute_an_ordinary_compiler_program(self):
        self.guarded["physical_inputs"]["program"] = self.authority["program"]
        with self.assertRaisesRegex(reader.harness.HarnessError, "physical input authority changed"):
            self.read(native_only=True)
        self.assertEqual(self.executions, [])

    def test_guarded_profile_cannot_substitute_an_ordinary_command(self):
        self.contract["miri_guarded_ownership"] = {**self.contract["miri_ownership"], "features": ["mi-guarded"]}
        self.report["checks"]["miri-guarded-ownership"] = json.loads(json.dumps(self.ownership))
        with self.assertRaises(reader.harness.HarnessError):
            self.read(native_only=True)
        self.assertEqual(self.executions, [])

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
            selected_original = (json.loads((ROOT / self.guarded_authority["program"]["path"]).read_text())
                                 if 'feature="mi-guarded"' in private["args"] else original)
            args = list(selected_original["args"])
            out = args.index("--out-dir") + 1
            incremental = next(index + 1 for index, value in enumerate(args[:-1])
                               if value == "-C" and args[index + 1].startswith("incremental="))
            args[out] = private["args"][out]
            args[incremental] = private["args"][incremental]
            self.assertEqual(private, {**selected_original, "args": args})
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
        self.assertEqual(self.read(replay), self.report)
        self.assertEqual(len(observed), 7)
        self.assertEqual(json.loads((ROOT / self.authority["program"]["path"]).read_text()), original)

    def test_raw_group_order_survives_sorted_json_report_keys(self):
        self.producer.contract["miri"]["module_prefixes"] = ["fixture::second", "fixture::first"]
        self.contract["miri"] = self.producer.contract["miri"]
        miri, _calls = self.producer.execute()
        miri["physical_inputs"].update(self.authority)
        self.miri = json.loads(json.dumps(miri, sort_keys=True))
        self.report["checks"]["miri"] = self.miri
        def replay(command, timeout, **options):
            if "--list" in command:
                return self.miri["physical_inputs"]["listing"]
            return next(row for rows in self.miri["physical_inputs"]["commands"].values()
                        for row in rows if row["command"][-1] == command[-1])
        self.assertEqual(self.read(replay), self.report)
        self.assertEqual(sum(call.args[0][0] == self.authority["tools"]["cargo-miri"]["executable_path"]
                             for call in self.executions), 7)

    def test_wrong_pinned_tool_directory_is_rejected_before_interpretation(self):
        self.authority["tools"]["miri"]["executable_path"] = "/ambient/bin/miri"
        with self.assertRaisesRegex(reader.harness.HarnessError, "pinned source toolchain"):
            self.read()
        self.assertEqual(self.executions, [])


if __name__ == "__main__":
    unittest.main()
