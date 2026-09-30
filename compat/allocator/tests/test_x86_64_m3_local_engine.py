#!/usr/bin/env python3
"""Fail-closed checks for source-bound local primitive trace coverage."""

from __future__ import annotations

import copy
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("m3_x86_64", ROOT / "compat/allocator/m3_x86_64.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


RETIREMENT_TRACE = """M3R start regular=ABC full= direct=A state=RRR bytes=0 pages=3
M3R retire-head regular=BC full= direct=B state=DRR bytes=0 pages=2
M3R reuse-tail regular=BCA full= direct=B state=RRR bytes=0 pages=3
M3R move-head regular=CBA full= direct=C state=RRR bytes=0 pages=3
M3R full-head regular=BA full=C direct=B state=RRF bytes=256 pages=3
M3R full-next regular=A full=CB direct=A state=RFF bytes=448 pages=3
M3R retire-last-regular regular= full=CB direct=- state=DFF bytes=448 pages=2
M3R reuse-from-full regular=C full=B direct=C state=DFR bytes=192 pages=2
M3R retire-full regular=C full= direct=C state=DDR bytes=0 pages=1
M3R retire-final regular= full= direct=- state=DDD bytes=0 pages=0
"""


class LocalPrimitiveTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = gate.load_contract()

    def read_trace(self, trace: str):
        with tempfile.TemporaryDirectory(prefix="m3-reader-", dir=ROOT / ".work") as directory:
            with mock.patch.object(gate, "ARTIFACT_ROOT", Path(directory)):
                with mock.patch.object(gate.run, "command_record", return_value={"status": 0, "stdout": trace, "stderr": ""}):
                    return gate.run_queue_retirement_differential(self.contract)

    def test_one_retirement_sequence_cannot_qualify_bin_and_free_list_parity(self) -> None:
        result = self.read_trace(RETIREMENT_TRACE)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("queue matrix did not execute bin" in item for item in result["unmet"]))
        self.assertTrue(any("free-list matrix did not execute every source mode" in item for item in result["unmet"]))

    def test_a_cache_snapshot_must_match_the_queue_and_unrelated_live_bin(self) -> None:
        trace = RETIREMENT_TRACE + (
            "M3B bin=4 size=32 seed=331572594510 step=0 action=init page=- regular= full= "
            f"direct={'A' * 129} state=DDD bytes=0 pages=1 sentinel=1\n"
        )
        result = self.read_trace(trace)
        self.assertTrue(any("owner/cache/transition invariant" in item for item in result["unmet"]))

    def test_a_free_list_cannot_own_an_allocated_block(self) -> None:
        trace = RETIREMENT_TRACE + "M3F size=32 stage=exhausted capacity=4 reserved=4 used=4 zero=0 free=0 local=-\n"
        result = self.read_trace(trace)
        self.assertTrue(any("initialized ownership/counts" in item for item in result["unmet"]))

    def test_green_local_checks_preserve_incomplete_prerequisites(self) -> None:
        checks = {check: {"status": "passed"} for component in self.contract["components"] for check in component["checks"]}
        checks["prerequisites"] = {"milestones": {}, "unmet": ["M1 and M2 receipts are absent"]}
        result = gate.evaluate_gate(self.contract, checks)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(all(component["status"] == "complete" for component in result["components"]))

    def test_a_failed_required_check_cannot_be_hidden_by_omitting_its_component(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["components"] = [component for component in contract["components"] if component["id"] != "miri-execution"]
        checks = {check: {"status": "passed"} for component in self.contract["components"] for check in component["checks"]}
        checks["miri"] = {"status": "failed", "unmet": ["undefined behaviour"]}
        checks["prerequisites"] = {"milestones": {}, "unmet": []}
        with self.assertRaisesRegex(gate.GateError, "required checks.*miri"):
            gate.evaluate_gate(contract, checks)


class LocalEngineSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="m3-source-", dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name)
        self.source = self.fixture / "source-file"
        self.source.write_text("initial\n")
        self.git("init", "--quiet")
        self.commit_source()

    def git(self, *arguments: str) -> None:
        subprocess.run(
            ("git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
             "-c", "user.name=Source regression", "-c", "user.email=source@example.invalid", *arguments),
            cwd=self.fixture, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )

    def commit_source(self) -> None:
        self.git("add", "source-file")
        self.git("commit", "--quiet", "--no-verify", "-m", "source fixture")

    def native_environment(self):
        return {
            "CRABC_EXECUTION_MODE": "native",
            "CRABC_HOST_ARCH": "x86_64",
            "CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID": "sha256:" + "4" * 64,
        }

    def execute(self, mutation=None, arguments=None, environment=None):
        reports = []
        executed = []

        def differential(*arguments, **keywords):
            executed.append("differential")
            if mutation is not None:
                mutation()
            return {"status": "passed", "unmet": []}

        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            stack.enter_context(mock.patch.object(gate.run, "ROOT", self.fixture))
            native_environment = self.native_environment() if environment is None else environment
            inherited = {key: value for key, value in os.environ.items() if key not in self.native_environment()}
            stack.enter_context(mock.patch.dict(os.environ, {**inherited, **native_environment}, clear=True))
            stack.enter_context(mock.patch.object(gate.run.platform, "system", return_value="Linux"))
            stack.enter_context(mock.patch.object(gate.run.platform, "machine", return_value="x86_64"))
            stack.enter_context(mock.patch.object(gate.run, "write_json", side_effect=lambda path, report: reports.append(report)))
            stack.enter_context(mock.patch.object(gate, "rust_test_binary", return_value=self.fixture / "test-binary"))
            stack.enter_context(mock.patch.object(gate, "prerequisite_status", return_value={"milestones": {}, "unmet": []}))
            stack.enter_context(mock.patch.object(gate, "run_differential", side_effect=differential))
            for name in ("run_queue_reorder_differential", "run_queue_retirement_differential", "run_owner_differential", "run_unit_batch", "run_miri"):
                stack.enter_context(mock.patch.object(gate, name, return_value={"status": "passed", "unmet": []}))
            status = gate.main(arguments or [])
        return status, reports, executed

    def test_dirty_source_cannot_start_the_local_engine_gate(self) -> None:
        self.source.write_text("dirty\n")
        status, reports, executed = self.execute()
        self.assertEqual(status, 2)
        self.assertFalse(reports)
        self.assertFalse(executed)

    def test_source_edits_during_execution_cannot_publish_a_gate_receipt(self) -> None:
        status, reports, executed = self.execute(lambda: self.source.write_text("changed\n"))
        self.assertEqual(status, 2)
        self.assertFalse(reports)
        self.assertEqual(executed, ["differential"])

    def test_a_new_clean_commit_during_execution_cannot_publish_a_gate_receipt(self) -> None:
        def mutate():
            self.source.write_text("new commit\n")
            self.commit_source()

        status, reports, executed = self.execute(mutate)
        self.assertEqual(status, 2)
        self.assertFalse(reports)
        self.assertEqual(executed, ["differential"])

    def test_development_miri_subset_can_inspect_uncommitted_source(self) -> None:
        self.source.write_text("work in progress\n")
        status, reports, executed = self.execute(arguments=["--miri-only"])
        self.assertEqual(status, 0)
        self.assertFalse(executed)
        self.assertEqual(len(reports), 1)
        self.assertNotIn("milestone", reports[0])

    def test_gate_receipt_attests_one_unchanged_clean_source(self) -> None:
        status, reports, executed = self.execute()
        self.assertEqual(status, 0)
        self.assertEqual(executed, ["differential"])
        self.assertEqual(len(reports), 1)
        source = reports[0]["source"]
        self.assertTrue(source["unchanged_during_execution"])
        self.assertEqual(source["before"], source["after"])
        self.assertTrue(source["before"]["worktree_clean"])
        revision = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=self.fixture, text=True).strip()
        self.assertEqual(source["before"]["revision"], revision)


    def source_state(self):
        with mock.patch.object(gate.run, "ROOT", self.fixture):
            return gate.run.runtime_ticket_zero_soak_source_state()

    def prerequisite_receipt(self):
        source = self.source_state()
        return {
            "milestone": {"status": "complete"},
            "source": gate.run.runtime_ticket_zero_soak_source_attestation(source, source),
            "native_execution_provenance": {
                "execution_mode": "native", "host_architecture": "x86_64",
                "image_id": self.native_environment()["CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID"],
            },
        }

    def read_prerequisites(self, receipt, second=None):
        with tempfile.TemporaryDirectory(prefix="m3-prerequisites-", dir=ROOT / ".work/tmp") as directory:
            work = Path(directory)
            contract = gate.load_contract()
            for requirement, record in zip(contract["milestone"]["prerequisites"], (receipt, receipt if second is None else second)):
                path = work / requirement["report"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(record))
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(gate.run, "ROOT", self.fixture))
                stack.enter_context(mock.patch.object(gate.run, "WORK_ROOT", work))
                stack.enter_context(mock.patch.dict(os.environ, self.native_environment()))
                stack.enter_context(mock.patch.object(gate.run.platform, "system", return_value="Linux"))
                stack.enter_context(mock.patch.object(gate.run.platform, "machine", return_value="x86_64"))
                return gate.prerequisite_status(contract)

    def test_current_clean_native_prerequisites_can_qualify(self) -> None:
        self.assertFalse(self.read_prerequisites(self.prerequisite_receipt())["unmet"])

    def test_a_complete_receipt_from_a_previous_commit_cannot_qualify(self) -> None:
        receipt = self.prerequisite_receipt()
        self.source.write_text("new source\n")
        self.commit_source()
        result = self.read_prerequisites(receipt)
        self.assertTrue(any("source" in item for item in result["unmet"]))
        self.assertEqual(result["milestones"]["m1"]["status"], "complete")

    def test_complete_status_cannot_replace_a_clean_unchanged_source_attestation(self) -> None:
        for mutation in ("absent", "dirty", "changed", "unstable", "corrupt-status"):
            with self.subTest(mutation=mutation):
                receipt = self.prerequisite_receipt()
                if mutation == "absent":
                    del receipt["source"]
                elif mutation == "dirty":
                    for state in (receipt["source"]["before"], receipt["source"]["after"]):
                        state["worktree_clean"] = False
                        state["worktree_status"] = gate.run.source_byte_record(b" M source-file\0")
                elif mutation == "changed":
                    receipt["source"]["after"]["revision"] = "0" * 40
                elif mutation == "unstable":
                    receipt["source"]["unchanged_during_execution"] = False
                else:
                    receipt["source"]["before"]["worktree_status"]["sha256"] = "0" * 64
                result = self.read_prerequisites(receipt)
                self.assertTrue(any("source" in item for item in result["unmet"]))
                self.assertEqual(result["milestones"]["m1"]["status"], "complete")

    def test_complete_status_cannot_replace_current_native_image_provenance(self) -> None:
        for mutation in ("absent", "different", "mutable", "emulated", "foreign-host"):
            with self.subTest(mutation=mutation):
                receipt = self.prerequisite_receipt()
                if mutation == "absent":
                    del receipt["native_execution_provenance"]
                elif mutation == "different":
                    receipt["native_execution_provenance"]["image_id"] = "sha256:" + "5" * 64
                elif mutation == "mutable":
                    receipt["native_execution_provenance"]["image_id"] = "allocator:current"
                elif mutation == "emulated":
                    receipt["native_execution_provenance"]["execution_mode"] = "emulated"
                else:
                    receipt["native_execution_provenance"]["host_architecture"] = "aarch64"
                result = self.read_prerequisites(receipt)
                self.assertTrue(any("native execution" in item for item in result["unmet"]))
                self.assertEqual(result["milestones"]["m1"]["status"], "complete")

    def test_current_partial_prerequisite_stays_partial(self) -> None:
        first = self.prerequisite_receipt()
        second = copy.deepcopy(first)
        second["milestone"]["status"] = "partial"
        result = self.read_prerequisites(first, second)
        self.assertEqual(result["milestones"]["m2"]["status"], "partial")
        self.assertEqual(result["unmet"], ["prerequisite M2 is partial, not complete"])

    def test_missing_image_cannot_start_qualification(self) -> None:
        environment = self.native_environment()
        del environment["CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID"]
        status, reports, executed = self.execute(environment=environment)
        self.assertEqual(status, 2)
        self.assertFalse(reports)
        self.assertFalse(executed)

    def test_image_changes_during_execution_cannot_publish_a_gate_receipt(self) -> None:
        def mutate():
            os.environ["CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID"] = "sha256:" + "5" * 64
        status, reports, executed = self.execute(mutate)
        self.assertEqual(status, 2)
        self.assertFalse(reports)
        self.assertEqual(executed, ["differential"])

    def test_gate_receipt_attests_the_current_native_image(self) -> None:
        status, reports, _ = self.execute()
        self.assertEqual(status, 0)
        self.assertEqual(reports[0]["native_execution_provenance"], {
            "execution_mode": "native", "host_architecture": "x86_64",
            "image_id": self.native_environment()["CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID"],
        })

    def test_development_subset_does_not_require_an_image_attestation(self) -> None:
        environment = self.native_environment()
        del environment["CRABC_ALLOCATOR_EVIDENCE_IMAGE_ID"]
        self.source.write_text("work in progress\n")
        status, reports, executed = self.execute(arguments=["--miri-only"], environment=environment)
        self.assertEqual(status, 0)
        self.assertFalse(executed)
        self.assertNotIn("milestone", reports[0])

def miri_input_fixture(directory: Path) -> Path:
    out = directory / "compiled/out"
    out.mkdir(parents=True)
    program = out / "crabc_mimalloc-fixture"
    dependency = out / "libcrabc_core-fixture.rlib"
    dependency.write_bytes(b"compiler-owned dependency fixture")
    (out / "crabc_core-fixture.d").write_text(f"{dependency}: crabc-core/src/lib.rs\n")
    program.with_suffix(".d").write_text(f"{program}: crabc-mimalloc/src/lib.rs\n")
    sysroot = directory / "miri-sysroot"
    libraries = sysroot / "lib/rustlib/x86_64-unknown-linux-gnu/lib"
    libraries.mkdir(parents=True)
    (libraries / "libstd-fixture.rlib").write_bytes(b"compiler-owned sysroot fixture")
    toolchain = directory / "toolchain"
    toolchain.mkdir()
    for name in ("cargo", "cargo-miri", "miri", "rustc"):
        tool = toolchain / name
        tool.write_text("#!/bin/sh\nprintf '%s\\n' 'fixture compiler version'\n")
        tool.chmod(0o755)
    selector = directory / "selector"
    selector.mkdir()
    rustup = selector / "rustup"
    rustup.write_text("#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n"
                      "print(Path(__file__).parent.parent / 'toolchain' / sys.argv[-1])\n")
    rustup.chmod(0o755)
    def encoded(value):
        return {"Unix": list(os.fsencode(value))}
    environment = {"RUSTC": str(toolchain / "miri"), "RUSTC_WRAPPER": str(toolchain / "cargo-miri"),
                   "MIRI_SYSROOT": str(sysroot), "MIRI_BE_RUSTC": "host"}
    program.write_text(json.dumps({"args": ["--crate-name", "crabc_mimalloc", "crabc-mimalloc/src/lib.rs",
        "--test", "--target", "x86_64-unknown-linux-gnu", "--out-dir", str(out),
        "-C", "incremental=" + str(out / "incremental"), "--extern", "crabc_core=" + str(dependency),
        "-L", "dependency=" + str(out)],
        "env": [[encoded(key), encoded(value)] for key, value in environment.items()],
        "current_dir": encoded(str(ROOT)), "stdin": []}))
    return program


class MiriWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="miri-storage-", dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name)
        self.program = miri_input_fixture(self.fixture)
        self.boundary = self.fixture / "checkout/.work/allocator-x86_64/tmp"
        self.boundary.mkdir(parents=True)
        self.external = self.fixture / "image-cache"
        self.capture = self.fixture / "storage-paths"
        binary = self.fixture / "bin"
        binary.mkdir()
        cargo = binary / "cargo"
        cargo.write_text('''#!/usr/bin/env python3
import os
import sys
from pathlib import Path

arguments = sys.argv[1:]
if arguments == ["miri", "--version"]:
    print("miri fixture")
    sys.exit(0)

def storage(value):
    if value == "/tmp" or value.startswith("/tmp/"):
        return Path(os.environ["MIRI_TEST_TMP_MOUNT"]) / value.removeprefix("/tmp").lstrip("/")
    if value in ("/image-cache", "/image-sysroot"):
        return Path(os.environ["MIRI_TEST_IMAGE_STORAGE"]) / value.lstrip("/")
    raise RuntimeError("unexpected simulated container storage path")

cache = storage(os.environ.get("XDG_CACHE_HOME", "/image-cache"))
sysroot = storage(os.environ["MIRI_SYSROOT"]) if "MIRI_SYSROOT" in os.environ else cache / "miri"
for directory, marker in ((cache, "cache-write"), (sysroot, "sysroot-write")):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / marker).write_text("initialized")
    with Path(os.environ["MIRI_TEST_CAPTURE"]).open("a") as output:
        output.write(str(directory / marker) + "\\n")
if "--list" in arguments:
    print("Running unittests src/lib.rs (" + os.environ["MIRI_TEST_PROGRAM"] + ")", file=sys.stderr)
    print("fixture::allocation: test")
else:
    print("running 1 test")
    print("test fixture::allocation ... ok")
    print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out")
''')
        cargo.chmod(0o755)
        self.environment = {
            "PATH": f"{binary}:{self.fixture / 'selector'}:{os.environ['PATH']}",
            "MIRI_TEST_TMP_MOUNT": str(self.boundary),
            "MIRI_TEST_PROGRAM": str(self.program),
            "MIRI_TEST_IMAGE_STORAGE": str(self.external),
            "MIRI_TEST_CAPTURE": str(self.capture),
            "XDG_CACHE_HOME": "/image-cache",
        }
        self.contract = {"miri": {
            "target": "x86_64-unknown-linux-gnu",
            "miriflags": ["-Zmiri-strict-provenance"],
            "module_prefixes": ["fixture::"],
            "required_tests": ["fixture::allocation"],
        }}

    def execute(self, *, inherited_sysroot: bool) -> None:
        environment = dict(self.environment)
        if inherited_sysroot:
            environment["XDG_CACHE_HOME"] = "/tmp/inherited-cache"
            environment["MIRI_SYSROOT"] = "/image-sysroot"
        with mock.patch.dict(os.environ, environment):
            with mock.patch.object(gate, "ARTIFACT_ROOT", self.boundary / "artifacts"):
                result = gate.run_miri(self.contract)
        self.assertEqual(result["status"], "passed", result)
        for path in self.capture.read_text().splitlines():
            self.assertTrue(Path(path).resolve().is_relative_to(self.boundary), path)

    @unittest.skipUnless(
        Path("/opt/rustup/toolchains/nightly-2026-09-15-x86_64-unknown-linux-musl/bin/cargo-miri").is_file(),
        "requires the pinned allocator image's cargo-miri",
    )
    def test_pinned_miri_setup_builds_a_physical_checkout_owned_sysroot(self) -> None:
        command_record = gate.run.command_record
        selected = []

        def execute(command, **kwargs):
            if "--list" not in command:
                return command_record(command, **kwargs)
            setup = command_record(
                ("cargo", "miri", "setup", "--print-sysroot", "--target", self.contract["miri"]["target"]),
                **kwargs,
            )
            self.assertEqual(setup["status"], 0, setup)
            sysroot = Path(str(setup["stdout"]).strip()).resolve(strict=True)
            selected.append(sysroot)
            physical_tmp = Path("/tmp").resolve(strict=True)
            self.assertEqual(sysroot, physical_tmp / "crabc-m3-miri-cache/miri")
            self.assertTrue((sysroot / "lib/rustlib" / self.contract["miri"]["target"] / "lib").is_dir())
            print(f"Pinned Miri physical sysroot: {sysroot}", flush=True)
            return {"command": list(command), "status": 0, "stdout": "", "stderr": ""}

        environment = {"MIRI_SYSROOT": "/inherited-sysroot", "XDG_CACHE_HOME": "/tmp/inherited-cache"}
        with mock.patch.dict(os.environ, environment):
            with mock.patch.object(gate.run, "command_record", side_effect=execute):
                with mock.patch.object(gate, "ARTIFACT_ROOT", self.boundary / "artifacts"):
                    gate.run_miri(self.contract)
        self.assertEqual(len(selected), 1)

    def test_miri_cache_and_built_sysroot_use_the_checkout_tmp_mount(self) -> None:
        self.execute(inherited_sysroot=False)

    def test_an_inherited_sysroot_cannot_bypass_the_checkout_storage_boundary(self) -> None:
        self.execute(inherited_sysroot=True)


class MiriFreshInterpreterDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="miri-dispatch-", dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name)
        self.program = miri_input_fixture(self.fixture)
        self.capture = self.fixture / "dispatch.jsonl"
        binary = self.fixture / "bin"
        binary.mkdir()
        cargo = binary / "cargo"
        cargo.write_text('''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

arguments = sys.argv[1:]
if arguments == ["miri", "--version"]:
    print("miri fixture")
    sys.exit(0)
if "--list" in arguments:
    print("Running unittests src/lib.rs (" + os.environ["MIRI_TEST_PROGRAM"] + ")", file=sys.stderr)
    print("fixture::first: test")
    print("fixture::second: test")
    sys.exit(0)
selected = [name for name in arguments[arguments.index("--") + 1:] if not name.startswith("--")]
flags = os.environ.get("MIRIFLAGS", "").split()
marker = os.environ.get("CRABC_MIMALLOC_FRESH_TEST_CHILD")
with Path(os.environ["MIRI_DISPATCH_CAPTURE"]).open("a") as output:
    output.write(json.dumps({"arguments": arguments, "selected": selected,
                            "flags": flags, "marker": marker}) + "\\n")
if selected != [marker] or flags != ["-Zmiri-strict-provenance", "-Zmiri-env-forward=CRABC_MIMALLOC_FRESH_TEST_CHILD"]:
    print("isolated fixture attempted unsupported current_exe/readlink", file=sys.stderr)
    sys.exit(1)
name = selected[0]
mutate = os.environ.get("MIRI_DISPATCH_MUTATE_INPUT")
if mutate:
    Path(mutate).write_bytes(b"changed after compiler input capture")
failed = os.environ.get("MIRI_DISPATCH_FAIL") == name
print("running 1 test")
print("test " + name + " ... " + ("FAILED" if failed else "ok"))
print("test result: " + ("FAILED" if failed else "ok") + ". " +
      ("0 passed; 1 failed" if failed else "1 passed; 0 failed") +
      "; 0 ignored; 0 measured; 0 filtered out")
sys.exit(1 if failed else 0)
''')
        cargo.chmod(0o755)
        self.environment = {"PATH": f"{binary}:{self.fixture / 'selector'}:{os.environ['PATH']}",
            "MIRI_DISPATCH_CAPTURE": str(self.capture), "MIRI_TEST_PROGRAM": str(self.program),
            "CRABC_MIMALLOC_FRESH_TEST_CHILD": "fixture::wrong-inherited-child",
            "MIRIFLAGS": "-Zmiri-disable-isolation"}
        self.contract = {"miri": {"target": "x86_64-unknown-linux-gnu",
            "miriflags": ["-Zmiri-strict-provenance"], "module_prefixes": ["fixture::"],
            "required_tests": ["fixture::first", "fixture::second"]}}

    def execute(self, fail=None):
        environment = dict(self.environment)
        if fail is not None:
            environment["MIRI_DISPATCH_FAIL"] = fail
        with mock.patch.dict(os.environ, environment):
            with mock.patch.object(gate, "ARTIFACT_ROOT", self.fixture / "artifacts"):
                result = gate.run_miri(self.contract)
        calls = [json.loads(line) for line in self.capture.read_text().splitlines()]
        return result, calls

    def test_missing_compiler_runner_cannot_be_replaced_by_passing_test_labels(self) -> None:
        self.program.unlink()
        result, calls = self.execute()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["unmet"])
        self.assertEqual([call["selected"] for call in calls], [["fixture::first"], ["fixture::second"]])
        self.assertEqual(result["groups"]["fixture::"]["unreported"], [])

    def test_wrong_compiler_source_or_missing_dependency_cannot_supply_input_authority(self) -> None:
        original = self.program.read_text()
        for defect in ("crate", "source", "host", "tool", "dependency"):
            with self.subTest(defect=defect):
                metadata = json.loads(original)
                if defect == "crate":
                    metadata["args"][1] = "unrelated_library"
                elif defect == "source":
                    metadata["args"][2] = "unrelated/src/lib.rs"
                elif defect in ("host", "tool"):
                    name = "MIRI_BE_RUSTC" if defect == "host" else "RUSTC"
                    for key, value in metadata["env"]:
                        if bytes(key["Unix"]).decode() == name:
                            value["Unix"] = list(b"wrong_phase_or_tool")
                else:
                    metadata["args"][metadata["args"].index("--extern") + 1] = "crabc_core=" + str(self.fixture / "missing.rlib")
                self.program.write_text(json.dumps(metadata))
                result, _calls = self.execute()
                self.assertEqual(result["status"], "failed")
                self.assertTrue(result["unmet"])
        self.program.write_text(original)

    def test_changed_physical_dependency_is_not_hidden_by_passing_interpreter_labels(self) -> None:
        dependency = self.program.parent / "libcrabc_core-fixture.rlib"
        with mock.patch.dict(os.environ, {"MIRI_DISPATCH_MUTATE_INPUT": str(dependency)}):
            result, calls = self.execute()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["unmet"])
        self.assertEqual([call["selected"] for call in calls], [["fixture::first"], ["fixture::second"]])
        self.assertEqual(result["groups"]["fixture::"]["unreported"], [])

    def test_compiler_input_records_retain_the_selected_physical_bytes(self) -> None:
        result, _calls = self.execute()
        inputs = result["physical_inputs"]
        self.assertEqual(inputs["program"], gate.run.artifact_record(self.program))
        self.assertEqual(inputs["dep_info"], gate.run.artifact_record(self.program.with_suffix(".d")))
        for field in ("source_files", "dependencies", "dependency_info"):
            for record in inputs[field]:
                self.assertEqual(record, gate.run.artifact_record(ROOT / record["path"]))
        for record in inputs["sysroot"]["files"]:
            self.assertEqual(record, gate.run.artifact_record(ROOT / record["path"]))
        self.assertEqual(inputs["phase_environment"]["MIRI_BE_RUSTC"], "host")

    def test_each_selected_fixture_gets_a_fresh_exact_strict_interpreter(self) -> None:
        result, calls = self.execute()
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual([call["selected"] for call in calls], [["fixture::first"], ["fixture::second"]])
        self.assertEqual([call["marker"] for call in calls], ["fixture::first", "fixture::second"])
        for call in calls:
            self.assertIn("--exact", call["arguments"])
            self.assertIn("--test-threads=1", call["arguments"])
            self.assertEqual(call["flags"], ["-Zmiri-strict-provenance",
                "-Zmiri-env-forward=CRABC_MIMALLOC_FRESH_TEST_CHILD"])

    def test_retained_commands_bind_the_actual_fresh_interpreter_environment(self) -> None:
        result, calls = self.execute()
        records = result["physical_inputs"]["commands"]["fixture::"]
        for record, observed in zip(records, calls, strict=True):
            environment = record["environment"]
            self.assertEqual(environment["MIRIFLAGS"], " ".join(observed["flags"]))
            self.assertEqual(environment[gate.FRESH_TEST_CHILD_ENV], observed["marker"])
            self.assertEqual(environment["TMPDIR"], "/tmp")
            self.assertEqual(environment["XDG_CACHE_HOME"], "/tmp/crabc-m3-miri-cache")
        self.assertNotIn(gate.FRESH_TEST_CHILD_ENV, result["physical_inputs"]["listing"]["environment"])

    def test_a_failed_fixture_does_not_hide_the_remaining_selected_fixture(self) -> None:
        result, calls = self.execute("fixture::first")
        self.assertEqual(result["status"], "failed", result)
        self.assertEqual([call["selected"] for call in calls], [["fixture::first"], ["fixture::second"]])
        self.assertEqual(result["groups"]["fixture::"]["failed"], ["fixture::first"])
        self.assertEqual(result["groups"]["fixture::"]["passed"], 1)
        self.assertEqual(result["groups"]["fixture::"]["unreported"], [])


if __name__ == "__main__":
    unittest.main()
