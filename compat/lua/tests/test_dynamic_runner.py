#!/usr/bin/env python3
"""Host-side contract tests for the native dynamic Lua dispatcher."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
CHECKOUT_ROOT = (
    ROOT.parents[2]
    if ROOT.parent.name == "worktrees" and ROOT.parent.parent.name == ".work"
    else ROOT
)
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


class NativeDynamicHeaderSelectionTests(unittest.TestCase):
    """The installed dynamic driver records the actual selected public headers."""

    scratch_root = ROOT / ".work" / "lua-dynamic-header-selection-host-tests"

    def setUp(self) -> None:
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="headers-", dir=self.scratch_root))
        self.addCleanup(shutil.rmtree, self.temporary, ignore_errors=True)
        self.sysroot = self.temporary / "sysroot"
        self.headers = self.sysroot / "usr/include"
        self.headers.mkdir(parents=True)
        self.installed_header = self.headers / "stdio.h"
        self.installed_header.write_text("/* owned stdio */\n", encoding="utf-8")
        self.work = self.temporary / "work"
        self.work.mkdir()
        self.wrapper = self.temporary / "crabc-cc-dynamic"
        self.wrapper.write_text("sealed wrapper\n", encoding="utf-8")

    def command_with_dependencies(self, dependencies: str) -> mock.Mock:
        def invoke(arguments: object, *, work: Path, state: Path, timeout: float) -> dict[str, object]:
            assert isinstance(arguments, list)
            dependency = Path(arguments[arguments.index("--application-dependency-file") + 1])
            dependency.write_text(dependencies, encoding="utf-8")
            output = Path(arguments[arguments.index("-o") + 1])
            output.write_bytes(b"owned header probe object\n")
            return {
                "status": 0,
                "stdout": RUNNER.LUA.stream_record(b""),
                "stderr": RUNNER.LUA.stream_record(b""),
            }

        return mock.Mock(side_effect=invoke)

    def test_header_probe_records_only_installed_header_dependencies(self) -> None:
        command = self.command_with_dependencies(
            f"{self.work / 'header-probe.o'}: {RUNNER.FIXTURES / 'header_probe.c'} {self.installed_header}\n"
        )
        with mock.patch.object(RUNNER, "command", command):
            record = RUNNER.dynamic_header_probe(
                self.wrapper,
                RUNNER.dynamic_flags(),
                self.work,
                self.sysroot,
                timeout=5.0,
            )

        arguments = command.call_args.args[0]
        self.assertEqual(arguments[0:2], [str(self.wrapper), "--dynamic-shared-object"])
        self.assertIn("--application-dependency-file", arguments)
        self.assertIn("-c", arguments)
        audit = record["header_dependency_audit"]
        self.assertEqual(audit["status"], "passed")
        self.assertEqual(audit["target"], str((self.work / "header-probe.o").resolve()))
        self.assertEqual(audit["headers"], [str(self.installed_header.resolve())])
        self.assertEqual(audit["ambient_headers"], [])

    def test_header_probe_rejects_an_ambient_dependency(self) -> None:
        command = self.command_with_dependencies(
            f"{self.work / 'header-probe.o'}: {RUNNER.FIXTURES / 'header_probe.c'} /usr/include/stdio.h\n"
        )
        with mock.patch.object(RUNNER, "command", command):
            with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "ambient or foreign header"):
                RUNNER.dynamic_header_probe(
                    self.wrapper,
                    RUNNER.dynamic_flags(),
                    self.work,
                    self.sysroot,
                    timeout=5.0,
                )

    @staticmethod
    def make_escape(path: Path) -> str:
        return (
            str(path)
            .replace("\\", "\\\\")
            .replace("$", "$$")
            .replace("#", "\\#")
            .replace(":", "\\:")
            .replace(" ", "\\ ")
        )

    def test_make_dependency_paths_decode_gcc_escaping(self) -> None:
        source = self.temporary / "source space#colon:quote\"single'$cash\\slash.c"
        source.write_text("int source;\n", encoding="utf-8")
        header = self.headers / "header space#colon:quote\"single'$cash\\slash.h"
        header.write_text("/* owned header */\n", encoding="utf-8")
        output = self.work / "target space#colon:quote\"single'$cash\\slash.o"
        output.write_bytes(b"owned header probe object\n")
        dependency = self.work / "header-probe.d"
        source_rule = self.make_escape(source)
        header_rule = self.make_escape(header)
        target_rule = self.make_escape(output)
        cases = {
            "single-line": f"{target_rule}: {source_rule} {header_rule}\n",
            "continued": f"{target_rule}: {source_rule} \\\n {header_rule}\n",
        }

        for label, rule in cases.items():
            with self.subTest(label=label):
                dependency.write_text(rule, encoding="utf-8")
                audit = RUNNER.dynamic_header_dependency_audit(
                    dependency, self.sysroot, source, output
                )
                self.assertEqual(audit["target"], str(output.resolve()))
                self.assertEqual(audit["source"], str(source.resolve()))
                self.assertEqual(audit["headers"], [str(header.resolve())])

    def test_target_terminator_follows_an_unescaped_whitespace(self) -> None:
        output = self.work / "target:physical.o"
        output.write_bytes(b"owned header probe object\n")
        paths = RUNNER.make_dependency_inputs(
            f"{output}: /source:physical.c /headers:physical.h\n", output
        )

        self.assertEqual(paths, ["/source:physical.c", "/headers:physical.h"])

    def test_header_dependency_rejects_a_mismatched_target(self) -> None:
        output = self.work / "header-probe.o"
        output.write_bytes(b"owned header probe object\n")
        foreign = self.work / "foreign.o"
        foreign.write_bytes(b"foreign object\n")
        dependency = self.work / "header-probe.d"
        dependency.write_text(
            f"{foreign}: {RUNNER.FIXTURES / 'header_probe.c'} {self.installed_header}\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "does not bind the generated object"):
            RUNNER.dynamic_header_dependency_audit(
                dependency, self.sysroot, RUNNER.FIXTURES / "header_probe.c", output
            )

    @unittest.skipUnless(shutil.which("gcc"), "requires GCC")
    def test_actual_gcc_dependency_paths_round_trip_make_escapes(self) -> None:
        source = self.temporary / "source space#colon:quote\"single'$cash\\slash.c"
        source.write_text("#include <stdio.h>\nint source;\n", encoding="utf-8")
        output_work = self.temporary / "work space#colon:quote\"single'$cash\\slash"
        output_work.mkdir()
        dependency = output_work / "header-probe.d"
        output = output_work / "header-probe.o"
        subprocess.run(
            [
                "gcc",
                "-nostdinc",
                "-isystem",
                str(self.headers),
                "-MD",
                "-MF",
                str(dependency),
                "-c",
                str(source),
                "-o",
                str(output),
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        audit = RUNNER.dynamic_header_dependency_audit(
            dependency, self.sysroot, source, output
        )
        self.assertEqual(audit["target"], str(output.resolve()))
        self.assertEqual(audit["source"], str(source.resolve()))
        self.assertEqual(audit["headers"], [str(self.installed_header.resolve())])


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


class NativeDynamicExecutionRootTests(unittest.TestCase):
    """Candidate Lua enters only a copied owned runtime root."""

    # Worktrees live below the checkout's ignored .work directory.  Container
    # probes may own a worktree-local .work mount, so keep host-test scratch in
    # the checkout-wide mutable x86 work area instead.
    scratch_root = CHECKOUT_ROOT / ".work/x86_64/tmp/lua-dynamic-execution-root-host-tests"

    def setUp(self) -> None:
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="root-", dir=self.scratch_root))
        self.addCleanup(shutil.rmtree, self.temporary, ignore_errors=True)
        self.product = self.temporary / "product"
        self.runtime = {
            "loader": self.product / "lib/ld-crabc-x86_64.so.1",
            "libc.so": self.product / "usr/lib/libc.so",
        }
        for path, contents in (
            (self.runtime["loader"], b"owned loader\n"),
            (self.runtime["libc.so"], b"owned libc\n"),
            (self.product / "bin/crabc-cc-dynamic", b"owned compiler\n"),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
        self.runtime["loader"].chmod(0o755)
        (self.product / "lib/ld-musl-x86_64.so.1").symlink_to(
            "ld-crabc-x86_64.so.1"
        )
        manifest = {
            "schema": 1,
            "format": RUNNER.FORMAT,
            "target": "x86_64-unknown-linux-musl",
            "symlinks": {"lib/ld-musl-x86_64.so.1": "ld-crabc-x86_64.so.1"},
            "files": {
                path.relative_to(self.product).as_posix(): RUNNER.LUA.sha256_file(path)
                for path in (
                    self.runtime["loader"],
                    self.runtime["libc.so"],
                    self.product / "bin/crabc-cc-dynamic",
                )
            },
        }
        manifest_path = self.product / "share/crabc/manifest.json"
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        self.application = self.temporary / "application"
        binaries = self.application / "bin"
        libraries = self.application / "lib"
        for path, contents in (
            (binaries / "lua", b"candidate lua\n"),
            (binaries / "luac", b"candidate luac\n"),
            (libraries / "liblua.so.5.4", b"candidate liblua\n"),
            (libraries / "crabc_probe.so", b"candidate probe\n"),
            (libraries / "crabc_fail.so", b"candidate fail\n"),
            (libraries / "crabc_missing.so", b"candidate missing\n"),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
            path.chmod(0o755)
        self.candidate = {
            "lua": binaries / "lua",
            "luac": binaries / "luac",
            "libraries": libraries,
        }
        self.script = self.temporary / "exercise.lua"
        self.script.write_text("return true\n", encoding="utf-8")
        self.shell = self.temporary / "fixture-shell"
        self.shell.write_bytes(b"sealed shell\n")
        self.shell.chmod(0o755)
        self.shell_loader = self.temporary / "fixture-loader"
        self.shell_loader.write_bytes(b"sealed shell loader\n")
        self.shell_loader.chmod(0o755)
        self.execution = self.temporary / "execution"

    def root(self) -> dict[str, object]:
        return RUNNER.prepare_candidate_execution_root(
            sysroot=self.product,
            runtime=self.runtime,
            candidate=self.candidate,
            script=self.script,
            execution_root=self.execution,
            shell=self.shell,
            shell_loader=self.shell_loader,
            shell_loader_closure={
                "command": {"status": 0},
                "closure": ["/lib/ld-musl-x86_64.so.1"],
                "required_in_root_path": "lib/ld-musl-x86_64.so.1",
                "qualified_loader": RUNNER.LUA.artifact_record(self.shell_loader),
            },
        )

    def test_private_root_binds_product_app_script_and_only_shell_alias_exception(self) -> None:
        record = self.root()

        self.assertEqual(record["root"], str(self.execution.resolve()))
        self.assertEqual(
            RUNNER.LUA.sha256_file(self.execution / "lib/ld-crabc-x86_64.so.1"),
            RUNNER.LUA.sha256_file(self.runtime["loader"]),
        )
        self.assertEqual(
            RUNNER.LUA.sha256_file(self.execution / "usr/lib/libc.so"),
            RUNNER.LUA.sha256_file(self.runtime["libc.so"]),
        )
        self.assertEqual(
            RUNNER.LUA.sha256_file(self.execution / "application/bin/luac"),
            RUNNER.LUA.sha256_file(self.candidate["luac"]),
        )
        self.assertFalse((self.execution / "lib/ld-musl-x86_64.so.1").is_symlink())
        self.assertEqual(
            RUNNER.LUA.sha256_file(self.execution / "lib/ld-musl-x86_64.so.1"),
            RUNNER.LUA.sha256_file(self.shell_loader),
        )
        self.assertEqual(
            record["kernel_luac_command"],
            ["/usr/sbin/chroot", str(self.execution.resolve()), "/application/bin/luac"],
        )
        audit = RUNNER.audit_candidate_execution_root(record)
        self.assertEqual(audit["status"], "passed")
        self.assertEqual(
            audit["entries"]["application/bin/luac"]["sha256"],
            RUNNER.LUA.sha256_file(self.candidate["luac"]),
        )

        (self.execution / "application/bin/lua").write_bytes(b"tampered\n")
        with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "application payload"):
            RUNNER.audit_candidate_execution_root(record)

    def test_map_proof_uses_the_live_chroot_root_and_rejects_outside_paths(self) -> None:
        self.root()
        physical = str(self.execution.resolve())
        maps = "\n".join(
            (
                f"00400000-00401000 r-xp 00000000 00:00 0 {physical}/lib/ld-crabc-x86_64.so.1",
                "00500000-00501000 r--p 00000000 00:00 0 /usr/lib/libc.so",
                f"00600000-00601000 r--p 00000000 00:00 0 {physical}/application/lib/liblua.so.5.4",
                "00700000-00701000 r--p 00000000 00:00 0 /application/lib/crabc_probe.so",
            )
        )
        record = RUNNER.verify_candidate_maps(
            maps,
            self.runtime,
            self.candidate["libraries"],
            execution_root=self.execution,
        )
        self.assertEqual(record["status"], "passed")
        self.assertEqual(record["process_root"], str(self.execution.resolve()))

        with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "outside the private execution root"):
            RUNNER.verify_candidate_maps(
                maps + f"\n00800000-00801000 r--p 00000000 00:00 0 {physical}/outside.so",
                self.runtime,
                self.candidate["libraries"],
                execution_root=self.execution,
            )

    def test_private_root_rejects_a_resealed_product_copy(self) -> None:
        record = self.root()
        (self.execution / "usr/lib/libc.so").write_bytes(b"substituted libc\n")

        with self.assertRaisesRegex(RUNNER.ExecutionRootAuditError, "immutable application payload or roster drifted") as raised:
            RUNNER.audit_candidate_execution_root(record)
        self.assertEqual(raised.exception.audit["status"], "rejected")
        self.assertEqual(
            raised.exception.audit["entries"]["usr/lib/libc.so"]["sha256"],
            RUNNER.LUA.sha256_file(self.execution / "usr/lib/libc.so"),
        )

    def test_private_root_rejects_an_extra_loader_policy_file(self) -> None:
        record = self.root()
        policy = self.execution / "etc/ld-musl-x86_64.path"
        policy.parent.mkdir()
        policy.write_text("/foreign/lib\n", encoding="utf-8")

        with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "etc/ld-musl-x86_64.path"):
            RUNNER.audit_candidate_execution_root(record)

    def test_private_root_rejects_root_permission_drift(self) -> None:
        record = self.root()
        self.execution.chmod(0o700)

        with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "root mode drifted"):
            RUNNER.audit_candidate_execution_root(record)

    def test_shell_ldd_closure_requires_only_the_pinned_loader_path(self) -> None:
        self.assertEqual(
            RUNNER._shell_ldd_closure(
                "\t/lib/ld-musl-x86_64.so.1 (0x7f0000000000)\n"
                "\tlibc.musl-x86_64.so.1 => /lib/ld-musl-x86_64.so.1 (0x7f0000000000)\n"
            ),
            ("/lib/ld-musl-x86_64.so.1",),
        )
        with self.assertRaisesRegex(RUNNER.LUA.RunnerError, "closure differs"):
            RUNNER._shell_ldd_closure("\t/lib/ld-musl-x86_64.so.1 (0x0)\n\t/lib/foreign.so (0x0)\n")

    def test_partial_maps_ready_is_bounded_and_cleans_its_process_group(self) -> None:
        """A partial protocol marker cannot block a buffered ``readline`` forever."""

        child = (
            "import sys, time; "
            "sys.stdout.write('maps-ready'); sys.stdout.flush(); time.sleep(30)"
        )

        def outer_timeout(_signal: int, _frame: object) -> None:
            raise TimeoutError("run_chroot_lua readiness read exceeded the test bound")

        previous = signal.signal(signal.SIGALRM, outer_timeout)
        signal.setitimer(signal.ITIMER_REAL, 2.0)
        try:
            started = time.monotonic()
            with mock.patch.object(RUNNER, "_chroot_command", return_value=[sys.executable, "-c", child]):
                result, maps, process_root = RUNNER.run_chroot_lua(
                    execution_root=self.temporary,
                    program="/application/bin/lua",
                    script="/work/exercise.lua",
                    fixture="/work/fixture-state/source-candidate",
                    timeout=0.1,
                    capture_maps=False,
                )
            elapsed = time.monotonic() - started
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, previous)

        self.assertEqual(result.status, "TIMEOUT")
        self.assertTrue(result.timed_out)
        self.assertEqual(result.stdout, b"maps-ready")
        self.assertIsNone(maps)
        self.assertIsNone(process_root)
        self.assertLess(elapsed, 1.0)


class NativeDynamicFailureRetentionTests(unittest.TestCase):
    """A failed runtime command still leaves its sealed build and raw output."""

    scratch_root = CHECKOUT_ROOT / ".work/x86_64/tmp/lua-dynamic-failure-retention-host-tests"

    def setUp(self) -> None:
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="failure-", dir=self.scratch_root))
        self.addCleanup(shutil.rmtree, self.temporary, ignore_errors=True)
        self.archive = self.temporary / "lua.tar.gz"
        self.archive.write_bytes(b"archive\n")
        self.wrapper = self.temporary / "crabc-cc-dynamic"
        self.wrapper.write_bytes(b"wrapper\n")
        self.runtime = {
            "headers": self.temporary / "usr/include",
            "loader": self.temporary / "lib/ld-crabc-x86_64.so.1",
            "libc.so": self.temporary / "usr/lib/libc.so",
        }
        self.runtime["headers"].mkdir(parents=True)
        for name, path in self.runtime.items():
            if name == "headers":
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(path.name.encode())

    def test_lane_keeps_candidate_reference_and_failed_luac_record(self) -> None:
        candidate = {
            "paths": {"lua": self.temporary / "lua", "luac": self.temporary / "luac", "libraries": self.temporary},
            "records": {"artifacts": {"sentinel": "candidate"}},
        }
        reference = {
            "paths": {"lua": self.temporary / "oracle-lua", "luac": self.temporary / "oracle-luac", "libraries": self.temporary},
            "records": {"artifacts": {"sentinel": "reference"}},
        }
        failed_luac = {
            "command": ["/usr/sbin/chroot", "/private-root", "/application/bin/luac"],
            "cwd": "/private-root",
            "status": 127,
            "stdout": RUNNER.LUA.stream_record(b""),
            "stderr": RUNNER.LUA.stream_record(b"libcidentity\n"),
        }
        failure = RUNNER.DynamicWorkloadFailure(
            "candidate dynamic luac bytecode build failed: 127", {"candidate_luac": failed_luac}
        )
        source = self.temporary / "source"
        source.mkdir()
        work = self.temporary / "work"
        work.mkdir()
        with (
            mock.patch.object(RUNNER, "require_native_x86_64"),
            mock.patch.object(RUNNER.LUA, "native_work_root", return_value=work),
            mock.patch.object(RUNNER.LUA, "load_manifest", return_value={"lua": {"archive_root": "lua-5.4.8"}}),
            mock.patch.object(RUNNER.LUA, "fetch_archive", return_value=self.archive),
            mock.patch.object(RUNNER, "owned_dynamic_sysroot", return_value=(self.temporary, self.wrapper, self.runtime, {})),
            mock.patch.object(RUNNER.LUA, "safe_extract", return_value=source),
            mock.patch.object(RUNNER, "build_candidate", return_value=candidate),
            mock.patch.object(RUNNER, "build_reference", return_value=reference),
            mock.patch.object(RUNNER, "run_workloads", side_effect=failure),
            mock.patch.object(RUNNER, "require_regular", side_effect=lambda _path, _description: self.wrapper),
        ):
            report = RUNNER.run_dynamic_lane(
                sysroot_path=self.temporary,
                work_root=work,
                cache=self.temporary / "cache",
                offline=True,
                jobs=1,
                timeout=1.0,
            )

        self.assertFalse(report["passed"])
        self.assertEqual(report["candidate"], candidate["records"])
        self.assertEqual(report["reference"], reference["records"])
        self.assertEqual(report["workloads"], {"candidate_luac": failed_luac})
        self.assertEqual(report["error"], "candidate dynamic luac bytecode build failed: 127")


if __name__ == "__main__":
    unittest.main()
