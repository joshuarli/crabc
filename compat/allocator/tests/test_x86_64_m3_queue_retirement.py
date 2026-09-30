"""Physical retention for the queue-retirement C/Rust component."""
from __future__ import annotations

import contextlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("queue_retirement", ROOT / "compat/allocator/x86_64_m3_queue_retirement.py")
assert spec is not None and spec.loader is not None
queue = importlib.util.module_from_spec(spec)
spec.loader.exec_module(queue)


class QueueRetirementRetentionTests(unittest.TestCase):
    def test_success_preserves_the_original_c_program_and_pinned_source(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp") as directory:
            root = Path(directory)
            archive = root / "upstream.tar.gz"
            archive.write_bytes(b"pinned source fixture")
            compiler = root / "compiler"
            compiler.write_bytes(b"compiler fixture")
            built = []
            extracted = []
            traces = {queue.RUST_TEST: "M3R source-shaped observation\n",
                      queue.RUST_MATRIX_TEST: "M3B source-shaped observation\n",
                      queue.RUST_FREE_TEST: "M3F source-shaped observation\n"}
            trace = "".join(traces.values())

            def extract(_archive, destination, _name):
                source = destination / "source"
                (source / "include").mkdir(parents=True)
                (source / "src").mkdir()
                (source / "src/static.c").write_text("original source\n")
                extracted.append(source)
                return source

            def command(argv, **_options):
                if "-o" in argv:
                    binary = Path(argv[argv.index("-o") + 1])
                    binary.write_bytes(b"original C program")
                    built.append(binary)
                    stdout = ""
                elif "--version" in argv or "-vV" in argv:
                    stdout = "compiler version fixture\n"
                elif any(name in argv for name in traces):
                    stdout = next(value for name, value in traces.items() if name in argv) + "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;\n"
                else:
                    stdout = trace
                return {"command": list(argv), "status": 0, "stdout": stdout, "stderr": ""}

            with contextlib.ExitStack() as stack:
                for name, value in (("ARTIFACT_ROOT", root / "artifacts"), ("TEMP_ROOT", root / "tmp")):
                    stack.enter_context(mock.patch.object(queue.run, name, value))
                stack.enter_context(mock.patch.object(queue.run, "require_native_x86_64", return_value={"image_id": "sha256:" + "1" * 64}))
                stack.enter_context(mock.patch.object(queue.run, "load_pin", return_value={"archive_root": "source"}))
                stack.enter_context(mock.patch.object(queue.run, "fetch_archive", return_value=archive))
                stack.enter_context(mock.patch.object(queue.run, "safe_extract", side_effect=extract))
                stack.enter_context(mock.patch.object(queue.run, "require_tool", return_value=str(compiler)))
                stack.enter_context(mock.patch.object(queue.run, "command_record", side_effect=command))
                program = root / "unit-program"
                program.write_bytes(b"original Rust program")
                stack.enter_context(mock.patch.object(queue.run, "_x86_64_unit_test_program", return_value={"path": program}))
                stack.enter_context(mock.patch.object(queue.run, "native_execution_attestation"))
                stack.enter_context(mock.patch.object(queue.receipts, "write_receipt"))
                self.assertEqual(queue.main(), 0)
            self.assertTrue(built[0].is_file(), "a receipt must retain the actual C executable")
            self.assertTrue((extracted[0] / "src/static.c").is_file(), "the original compiler input must remain physical")


class QueueRetirementReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        import hashlib
        import io
        import tarfile
        self.directory = tempfile.TemporaryDirectory(dir=ROOT / ".work/tmp")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(queue.run, "ARTIFACT_ROOT", self.root / "artifacts"))
        self.stack.enter_context(mock.patch.object(queue.run, "TEMP_ROOT", self.root / "scratch"))
        self.stack.enter_context(mock.patch.object(queue.receipts, "RECEIPTS", self.root.relative_to(ROOT) / "receipts"))
        work = self.root / "artifacts/queue-retirement-fixture"
        source = work / "source/upstream"
        (source / "src").mkdir(parents=True)
        (source / "include").mkdir()
        source_bytes = b"original pinned compiler input\n"
        (source / "src/static.c").write_bytes(source_bytes)
        (source / "src/alloc.c").write_bytes(source_bytes)
        (source / "include/mimalloc.h").write_bytes(source_bytes)
        archive = work / "upstream.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            for name in ("src/static.c", "src/alloc.c", "include/mimalloc.h"):
                item = tarfile.TarInfo("upstream/" + name)
                item.size = len(source_bytes)
                stream.addfile(item, io.BytesIO(source_bytes))
        pin = {"archive_root": "upstream", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        c_program = work / "m3-queue-retirement-c"
        c_program.write_bytes(b"original C executable")
        unit = work / "cargo-target/debug/deps/unit-test"
        unit.parent.mkdir(parents=True)
        unit.write_bytes(b"compiler-selected Rust executable")
        self.tool = work / "tool"
        self.tool.write_bytes(b"pinned tool fixture")
        execution = {"execution_mode": "native", "host_architecture": "x86_64", "image_id": "sha256:" + "1" * 64}
        self.stack.enter_context(mock.patch.object(queue.run, "require_native_x86_64", return_value=execution))
        self.stack.enter_context(mock.patch.object(queue.run, "load_pin", return_value=pin))
        self.stack.enter_context(mock.patch.object(queue.run, "require_tool", return_value=str(self.tool)))
        self.stack.enter_context(mock.patch.object(queue.run, "command_record", side_effect=self.command))
        tools = {name: {"path": str(self.tool), "sha256": queue.run.sha256_file(self.tool),
                       "version": self.command([str(self.tool), "-vV" if name == "rustc" else "--version"])}
                 for name in ("musl-gcc", "cargo", "rustc")}
        build_command = ["cargo", "test", "-p", "crabc-mimalloc", "--no-default-features", "--target",
                         "x86_64-unknown-linux-musl", "--locked", "--lib", "--no-run", "--message-format=json"]
        event = {"reason": "compiler-artifact", "target": {"name": "crabc_mimalloc", "kind": ["lib"]},
                 "profile": {"test": True}, "executable": str(unit)}
        build = {"command": build_command, "status": 0, "stdout": json.dumps(event), "stderr": ""}
        program = {"build": build, "build_command": build_command, "execution": queue.EXECUTION,
                   "cargo_target": str(work / "cargo-target"), "artifact": queue.run.artifact_record(unit)}
        self.lines = ["M3R retained row", "M3B retained row", "M3F retained row"]
        c_stdout = "\n".join(self.lines) + "\n"
        c_record = {"command": [str(c_program)], "status": 0, "stdout": c_stdout, "stderr": ""}
        rust_runs = [{"command": [str(unit), test, "--exact", "--nocapture", "--test-threads=1"],
                      "status": 0, "stdout": line + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;\n", "stderr": ""}
                     for test, line in zip(queue.TESTS, self.lines)]
        c_build = {"command": [str(self.tool), "-std=c11", "-ffunction-sections", "-fdata-sections",
                              "-Wl,--gc-sections", "-DMI_SHARED_LIB", "-DMI_SHARED_LIB_EXPORT", "-DMI_LIBC_MUSL=1",
                              *queue.run.CONFIGURATION_PROFILES["release"], "-I", str(source / "include"),
                              "-I", str(source / "src"), str(queue.C_FIXTURE), "-pthread", "-o", str(c_program)],
                   "status": 0, "stdout": "", "stderr": ""}
        self.report = {"archive_sha256": pin["sha256"], "pin": pin, "source": queue.receipts.source_seal(ROOT),
                       "execution": dict(execution), "work": queue.run.relative(work), "tools": tools,
                       "c_build": c_build, "c_runtime": c_record, "c_runtime_repeat": dict(c_record),
                       "rust_runtime": rust_runs, "physical_inputs": {"unit_program": program,
                           "c_program": queue.run.artifact_record(c_program), "archive": queue.run.artifact_record(archive),
                           "fixture": queue.run.artifact_record(queue.C_FIXTURE),
                           "oracle_source": queue.run.source_file_records(source, ["src/static.c", "src/alloc.c", "include/mimalloc.h"])}}
        self.work = work
        self.publish()

    def command(self, command, **_options):
        if "--version" in command or "-vV" in command:
            stdout = "pinned tool version\n"
        elif len(command) == 1:
            stdout = "\n".join(self.lines) + "\n"
        else:
            stdout = self.lines[queue.TESTS.index(command[1])] + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;\n"
        return {"command": list(command), "status": 0, "stdout": stdout, "stderr": ""}

    def publish(self) -> None:
        driver = self.work / "queue-retirement-driver.json"
        queue.run.write_json(driver, self.report)
        c_log = self.work / "c.trace"
        rust_log = self.work / "rust.trace"
        c_log.write_text(self.report["c_runtime"]["stdout"])
        rust_log.write_text("".join(row["stdout"] for row in self.report["rust_runtime"]))
        physical = self.report["physical_inputs"]
        queue.receipts.write_receipt(ROOT, queue.RECEIPT_RUNNER, self.work,
            {"queue-retirement-driver.json": driver, "c-program": ROOT / physical["c_program"]["path"],
             "unit-program": ROOT / physical["unit_program"]["artifact"]["path"], "c-source": queue.C_FIXTURE,
             "upstream-archive": ROOT / physical["archive"]["path"]},
            [("c", 0, [c_log]), ("rust", 0, [rust_log])],
            {"configuration": "release", "test_threads": "1"}, canonical=True)

    def test_original_physical_inputs_read_and_replay(self) -> None:
        self.assertEqual(queue.read_report(), self.report)
        self.assertEqual(queue.read_report(replay=True), self.report)
        self.assertEqual(len(list((self.root / "scratch").glob("queue-replay-*/execution-*.json"))), 5)

    def test_forged_compiler_authority_is_rejected(self) -> None:
        import copy
        original = copy.deepcopy(self.report)
        for alteration in ("status", "package", "duplicate", "executable", "flags", "cargo_target"):
            with self.subTest(alteration=alteration):
                self.report = copy.deepcopy(original)
                program = self.report["physical_inputs"]["unit_program"]
                event = json.loads(program["build"]["stdout"])
                if alteration == "status":
                    program["build"]["status"] = 1
                elif alteration == "package":
                    event["target"]["name"] = "unrelated_library"
                    program["build"]["stdout"] = json.dumps(event)
                elif alteration == "duplicate":
                    program["build"]["stdout"] += "\n" + json.dumps(event)
                elif alteration == "executable":
                    event["executable"] = str(self.work / "replacement")
                    program["build"]["stdout"] = json.dumps(event)
                elif alteration == "flags":
                    program["build_command"] = ["cargo", "test", "--all-features"]
                    program["build"]["command"] = program["build_command"]
                else:
                    program["cargo_target"] = str(self.root)
                self.publish()
                with self.assertRaises(queue.run.HarnessError):
                    queue.read_report()

    def test_original_program_tampering_is_rejected(self) -> None:
        path = ROOT / self.report["physical_inputs"]["c_program"]["path"]
        path.write_bytes(b"changed executable")
        with self.assertRaises(queue.run.HarnessError):
            queue.read_report()

    def test_forged_execution_roster_is_rejected(self) -> None:
        self.report["rust_runtime"][0]["command"][1] = queue.RUST_FREE_TEST
        self.publish()
        with self.assertRaises(queue.run.HarnessError):
            queue.read_report()

    def test_refreshed_original_oracle_records_cannot_override_the_pin(self) -> None:
        source = self.work / "source/upstream"
        (source / "src/static.c").write_text("changed pinned algorithm\n")
        self.report["physical_inputs"]["oracle_source"] = queue.run.source_file_records(source, ["src/static.c", "src/alloc.c", "include/mimalloc.h"])
        self.publish()
        with self.assertRaises(queue.run.HarnessError):
            queue.read_report()

    def test_changed_source_image_and_copied_program_are_rejected(self) -> None:
        with mock.patch.object(queue.receipts, "source_seal", return_value={"revision": "f" * 40, "worktree_sha256": "1" * 64}):
            with self.assertRaises(queue.receipts.ReceiptError):
                queue.read_report()
        self.report["execution"]["image_id"] = "sha256:" + "2" * 64
        self.publish()
        with self.assertRaises(queue.run.HarnessError):
            queue.read_report()
        retained = queue.receipts.receipt_directory(ROOT, queue.RECEIPT_RUNNER)
        (retained / "products/c-program").write_bytes(b"changed copy")
        with self.assertRaises(queue.receipts.ReceiptError):
            queue.read_report()
