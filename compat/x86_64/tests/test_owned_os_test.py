#!/usr/bin/env python3
"""Pure contract tests for the owned native os-test adapter."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import importlib.util
import json
import shlex
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "compat/x86_64/owned_os_test.py"
SPEC = importlib.util.spec_from_file_location("owned_os_test_test", MODULE)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)

sys.path.insert(0, str(MODULE.parent))
sys.modules["owned_os_test"] = RUNNER
TTYNAME_PROC_MODULE = ROOT / "compat/x86_64/owned_os_test_ttyname_proc.py"
TTYNAME_PROC_SPEC = importlib.util.spec_from_file_location("owned_os_test_ttyname_proc_test", TTYNAME_PROC_MODULE)
assert TTYNAME_PROC_SPEC is not None and TTYNAME_PROC_SPEC.loader is not None
TTYNAME_PROC = importlib.util.module_from_spec(TTYNAME_PROC_SPEC)
sys.modules[TTYNAME_PROC_SPEC.name] = TTYNAME_PROC
TTYNAME_PROC_SPEC.loader.exec_module(TTYNAME_PROC)


class TargetAdapterPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.product = ROOT / ".work/x86_64/owned-os-test-plan-product"
        (self.product / "usr/include").mkdir(parents=True, exist_ok=True)

    def test_compile_maps_only_documented_make_defaults(self) -> None:
        plan = RUNNER.target_plan(
            ["-c", "case.c", "-o", "case.o", "-fPIE", "-pthread", "-I" + str(self.product / "usr/include"),
             "-std=c17", "-Werror", "-D_POSIX_C_SOURCE=202405L"], self.product,
        )
        self.assertEqual(plan["kind"], "compile")
        self.assertEqual(plan["mode"], "pie")
        self.assertEqual(plan["source"], Path("case.c"))
        self.assertEqual(plan["output"], Path("case.o"))
        self.assertEqual(plan["flags"], ["-std=c17", "-Werror", "-D_POSIX_C_SOURCE=202405L"])
        self.assertEqual({change["raw"] for change in plan["changes"]}, {"-fPIE", "-pthread", "-I" + str(self.product / "usr/include")})

    def test_shared_source_is_split_into_retained_object_then_owned_link(self) -> None:
        plan = RUNNER.target_plan(
            ["-shared", "-fPIC", "-pthread", "-DSHARED", "dlfcn/dlopen.c", "-o", "dlfcn/dlopen.so"], self.product,
        )
        self.assertEqual(plan["kind"], "source-link")
        self.assertEqual(plan["mode"], "shared")
        self.assertEqual(plan["flags"], ["-DSHARED"])

    def test_source_shared_pie_conflict_is_retained_as_a_failure(self) -> None:
        with self.assertRaisesRegex(RUNNER.AdapterError, "incompatible -shared and -pie"):
            RUNNER.target_plan(["-shared", "-pie", "dlfcn/dlclose.c", "-o", "dlfcn/dlclose.so"], self.product)

    def test_link_maps_only_the_owned_libc_default_aliases(self) -> None:
        plan = RUNNER.target_plan(["case.o", "-o", "case", "-lm", "-lpthread", "-lrt"], self.product)
        self.assertEqual(plan["kind"], "link")
        self.assertEqual(plan["objects"], [Path("case.o")])
        self.assertEqual(plan["mode"], "pie")

    def test_foreign_include_is_an_adapter_error(self) -> None:
        with self.assertRaisesRegex(RUNNER.AdapterError, "unowned source include"):
            RUNNER.target_plan(["-c", "case.c", "-o", "case.o", "-I/foreign"], self.product)

    def test_foreign_library_is_an_adapter_error(self) -> None:
        with self.assertRaisesRegex(RUNNER.AdapterError, "unsupported os-test target flag"):
            RUNNER.target_plan(["case.o", "-o", "case", "-lcrypt"], self.product)

    def test_namespace_preprocessing_has_a_separate_non_target_plan(self) -> None:
        plan = RUNNER.target_plan(["-E", "-dM", "header.c", "-o", "header.dM", "-std=c17"], self.product)
        self.assertEqual(plan["kind"], "preprocess")
        self.assertTrue(plan["macro_dump"])
        self.assertEqual(plan["mode"], "preprocess")

    def test_make_recipes_preserve_frozen_defaults_and_only_suppress_unowned_linux_extras(self) -> None:
        source = ROOT / ".work/x86_64/owned-os-test-plan-source"
        evidence = ROOT / ".work/x86_64/owned-os-test-plan-evidence"
        runtime = ROOT / ".work/x86_64/owned-os-test-plan-runtime"
        include = RUNNER.make_command("include", source, MODULE, self.product, evidence, runtime, 7)
        process = RUNNER.make_command("process", source, MODULE, self.product, evidence, runtime, 7)
        musl = RUNNER.musl_make_command("basic", source, 7)
        self.assertIn("-j7", include)
        self.assertIn("-j1", process)
        for command in (include, process, musl):
            self.assertIn("EXTRA_LDFLAGS=", command)
            self.assertNotIn("CFLAGS=", command)
            self.assertNotIn("CPPFLAGS=", command)
            self.assertNotIn("LDFLAGS=", command)

        shared = RUNNER.target_plan(
            ["-shared", "-fPIC", "-DSHARED", "dlfcn/dlclose.c", "-o", "dlfcn/dlclose.so"], self.product,
        )
        self.assertEqual(shared["kind"], "source-link")
        self.assertEqual(shared["mode"], "shared")

    def test_make_adapter_quotes_each_path_in_the_shell_valued_compiler(self) -> None:
        root = ROOT / ".work/x86_64/owned os-test; no-shell"
        command = RUNNER.make_command("basic", root / "source path", MODULE, root / "product path",
                                      root / "evidence path", root / "runtime path", 1)
        compiler = next(value[3:] for value in command if value.startswith("CC="))
        self.assertEqual(shlex.split(compiler), [
            sys.executable, "-B", str(MODULE), "--adapter", "--product", str(root / "product path"),
            "--source-root", str(root / "source path"), "--evidence", str(root / "evidence path"),
            "--runtime-root", str(root / "runtime path"), "--",
        ])
        self.assertIn("'", compiler)


class EvidenceContractTests(unittest.TestCase):
    def assert_live_proc_root_is_not_walked(self, root: Path, lifecycle: dict[str, object]) -> None:
        proc = Path(lifecycle["receipt"]["mountpoint"])
        (proc / "live").mkdir(parents=True)
        (root / "records").mkdir()
        (root / "records" / "report.json").write_text("{}\n")
        original_lstat = Path.lstat

        def guarded_lstat(path: Path):
            if path == proc or path.is_relative_to(proc):
                raise AssertionError("host-readability walk entered the live procfs fixture")
            return original_lstat(path)

        live_proc_roots = {Path(item["receipt"]["mountpoint"])
                           for item in [lifecycle]
                           if not RUNNER.private_proc_lifecycle_postwalk_safe(item)}
        self.assertEqual(live_proc_roots, {proc})
        with mock.patch.object(Path, "lstat", guarded_lstat):
            RUNNER.make_evidence_host_readable(root, skip_roots=live_proc_roots)

    def test_basic_proc_reservation_and_mount_are_separate_from_the_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            private = RUNNER.reserve_private_proc_mountpoint(root, "basic")
            self.assertIsNotNone(private)
            assert private is not None
            self.assertEqual(private["mountpoint"], str(root / "proc"))
            self.assertEqual(private["reservation"], {"empty": True, "mode": 0o755})
            self.assertEqual(list((root / "proc").iterdir()), [])
            with self.assertRaisesRegex(RUNNER.RunnerError, "collides"):
                RUNNER.reserve_private_proc_mountpoint(root, "basic")
            self.assertIsNone(RUNNER.reserve_private_proc_mountpoint(root, "pty"))

            with mock.patch.object(RUNNER, "container_pid_namespace", return_value="pid:[42]"), \
                 mock.patch.object(RUNNER, "run_capture", side_effect=[
                     (0, b"", b""),
                     (0, b"pid:[42]\n", b""),
                 ]) as capture:
                RUNNER.mount_private_proc(root, private)

            self.assertEqual(
                capture.call_args_list[0].args[0],
                ["/bin/mount", "-t", "proc", "-o", "nosuid,nodev,noexec", "proc", str(root / "proc")],
            )
            self.assertEqual(private["mount"]["status"], 0)
            self.assertEqual(private["namespace"]["outside"], "pid:[42]")
            self.assertEqual(private["namespace"]["inside"]["stdout"], {"byte_length": 9,
                                                                              "sha256": hashlib.sha256(b"pid:[42]\n").hexdigest(),
                                                                              "text": "pid:[42]\n"})
            self.assertTrue(private["namespace"]["matched"])
            with mock.patch.object(RUNNER, "run_capture", return_value=(0, b"", b"")) as capture:
                unmount = RUNNER.unmount_private_proc(private)
            self.assertEqual(capture.call_args.args[0], ["/bin/umount", str(root / "proc")])
            self.assertEqual(unmount["status"], 0)

    def test_proc_mount_or_namespace_failure_never_reaches_candidate_execution(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            private = RUNNER.reserve_private_proc_mountpoint(root, "basic")
            assert private is not None
            with mock.patch.object(RUNNER, "run_capture", return_value=(32, b"", b"denied\n")) as capture:
                with self.assertRaisesRegex(RUNNER.FixtureError, "private procfs fixture setup failed"):
                    RUNNER.mount_private_proc(root, private)
            self.assertEqual(capture.call_count, 1)
            self.assertNotIn("namespace", private)

            (root / "second").mkdir()
            private = RUNNER.reserve_private_proc_mountpoint(root / "second", "basic")
            assert private is not None
            with mock.patch.object(RUNNER, "container_pid_namespace", return_value="pid:[42]"), \
                 mock.patch.object(RUNNER, "run_capture", side_effect=[
                     (0, b"", b""),
                     (0, b"pid:[43]\n", b""),
                 ]) as capture:
                with self.assertRaisesRegex(RUNNER.FixtureError, "PID namespace witness"):
                    RUNNER.mount_private_proc(root / "second", private)
            self.assertEqual(capture.call_count, 2)

    def test_interrupted_proc_mount_attempts_cleanup_and_skips_the_live_root(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            private = {"mountpoint": str(root / "proc")}
            lifecycle = RUNNER.private_proc_lifecycle(private)
            with mock.patch.object(RUNNER, "mount_private_proc", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    RUNNER.mount_private_proc_tracked(root, lifecycle)
            self.assertTrue(lifecycle["mount_pending"])
            self.assertFalse(RUNNER.private_proc_lifecycle_postwalk_safe(lifecycle))
            with mock.patch.object(RUNNER, "unmount_private_proc", return_value={"status": 1}) as unmount:
                RUNNER.unmount_private_proc_tracked(lifecycle)
            self.assertEqual(unmount.call_args.args[0], private)
            self.assertFalse(RUNNER.private_proc_lifecycle_postwalk_safe(lifecycle))
            self.assert_live_proc_root_is_not_walked(root, lifecycle)
            cleared_private = {"mountpoint": str(root / "cleared-proc")}
            cleared_lifecycle = RUNNER.private_proc_lifecycle(cleared_private)
            with mock.patch.object(RUNNER, "mount_private_proc", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    RUNNER.mount_private_proc_tracked(root, cleared_lifecycle)
            with mock.patch.object(RUNNER, "unmount_private_proc", return_value={"status": 0}) as cleared_unmount:
                RUNNER.unmount_private_proc_tracked(cleared_lifecycle)
            self.assertEqual(cleared_unmount.call_args.args[0], cleared_private)
            self.assertTrue(RUNNER.private_proc_lifecycle_postwalk_safe(cleared_lifecycle))

    def test_failed_proc_mount_receipt_attempts_cleanup_and_skips_the_live_root(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            private = {"mountpoint": str(root / "proc")}
            lifecycle = RUNNER.private_proc_lifecycle(private)

            def mount_failure(_destination: Path, receipt: dict[str, object]) -> None:
                receipt["mount"] = {"status": 32}
                raise RUNNER.FixtureError("private procfs fixture setup failed", {"private_proc": receipt})

            with mock.patch.object(RUNNER, "mount_private_proc", side_effect=mount_failure):
                with self.assertRaises(RUNNER.FixtureError):
                    RUNNER.mount_private_proc_tracked(root, lifecycle)
            self.assertTrue(lifecycle["mount_pending"])
            with mock.patch.object(RUNNER, "unmount_private_proc", return_value={"status": 1}) as unmount:
                RUNNER.unmount_private_proc_tracked(lifecycle)
            self.assertEqual(unmount.call_args.args[0], private)
            self.assertFalse(RUNNER.private_proc_lifecycle_postwalk_safe(lifecycle))
            self.assert_live_proc_root_is_not_walked(root, lifecycle)

    def test_proc_witness_failure_attempts_cleanup_and_skips_the_live_root(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            private = {"mountpoint": str(root / "proc")}
            lifecycle = RUNNER.private_proc_lifecycle(private)

            def witness_failure(_destination: Path, receipt: dict[str, object]) -> None:
                receipt["mount"] = {"status": 0}
                raise RUNNER.FixtureError("private procfs PID namespace witness failed", {"private_proc": receipt})

            with mock.patch.object(RUNNER, "mount_private_proc", side_effect=witness_failure):
                with self.assertRaises(RUNNER.FixtureError):
                    RUNNER.mount_private_proc_tracked(root, lifecycle)
            with mock.patch.object(RUNNER, "unmount_private_proc", return_value={"status": 1}) as unmount:
                RUNNER.unmount_private_proc_tracked(lifecycle)
            self.assertEqual(unmount.call_args.args[0], private)
            self.assertFalse(RUNNER.private_proc_lifecycle_postwalk_safe(lifecycle))
            self.assert_live_proc_root_is_not_walked(root, lifecycle)

    def test_failed_proc_unmount_skips_the_live_root(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            private = {"mountpoint": str(root / "proc")}
            lifecycle = RUNNER.private_proc_lifecycle(private)

            def successful_mount(_destination: Path, receipt: dict[str, object]) -> None:
                receipt["mount"] = {"status": 0}

            with mock.patch.object(RUNNER, "mount_private_proc", side_effect=successful_mount):
                RUNNER.mount_private_proc_tracked(root, lifecycle)
            with mock.patch.object(RUNNER, "unmount_private_proc", return_value={"status": 1}) as unmount:
                RUNNER.unmount_private_proc_tracked(lifecycle)
            self.assertEqual(unmount.call_args.args[0], private)
            self.assertFalse(RUNNER.private_proc_lifecycle_postwalk_safe(lifecycle))
            self.assert_live_proc_root_is_not_walked(root, lifecycle)

    def test_ttyname_proc_variant_registers_an_interrupted_mount_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            runtime = root / "runtime" / "with-proc"
            private = {"mountpoint": str(runtime / "proc")}
            control = {"root": str(runtime), "private_proc": private, "private_devpts": None}
            lifecycles: list[dict[str, object]] = []
            with mock.patch.object(TTYNAME_PROC.os_test, "prepare_execution_root", return_value=control), \
                 mock.patch.object(TTYNAME_PROC.os_test, "mount_private_proc", side_effect=KeyboardInterrupt), \
                 mock.patch.object(TTYNAME_PROC.os_test, "unmount_private_proc", return_value={"status": 1}) as unmount:
                with self.assertRaises(KeyboardInterrupt):
                    TTYNAME_PROC.run_variant(root, root / "product", root / "source", [], {}, {}, 1.0, "with-proc", lifecycles)
            self.assertEqual(len(lifecycles), 1)
            self.assertIs(lifecycles[0]["receipt"], private)
            self.assertEqual(unmount.call_args.args[0], private)
            self.assert_live_proc_root_is_not_walked(root, lifecycles[0])

    def test_ttyname_proc_profile_skips_an_interrupted_unreported_variant(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            product, source, work = root / "product", root / "source", root / "evidence"
            product.mkdir()
            source.mkdir()
            work.mkdir()
            proc = work / "runtime" / "with-proc" / "proc"
            values = SimpleNamespace(timeout=1.0, dynamic_sysroot=str(product), os_test_root=str(source))

            def interrupted_variant(_work: Path, _product: Path, _source: Path, _roster: list[dict[str, object]],
                                    _programs: dict[str, object], _environment: dict[str, str], _timeout: float,
                                    _variant: str, lifecycles: list[dict[str, object]]) -> dict[str, object]:
                private = {"mountpoint": str(proc)}
                lifecycle = RUNNER.private_proc_lifecycle(private)
                lifecycles.append(lifecycle)
                lifecycle["mount_pending"] = True
                (proc / "live").mkdir(parents=True)
                raise KeyboardInterrupt

            original_lstat = Path.lstat

            def guarded_lstat(path: Path):
                if path == proc or path.is_relative_to(proc):
                    raise AssertionError("host-readability walk entered the live procfs fixture")
                return original_lstat(path)

            static = SimpleNamespace(clean_environment=lambda: {
                "LC_ALL": "C", "PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "1", "TZ": "UTC",
            })
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict(TTYNAME_PROC.os.environ, {"TMPDIR": str(root)}, clear=False))
                stack.enter_context(mock.patch.object(TTYNAME_PROC.os_test, "physical_work_directory", side_effect=lambda value, _label: Path(value)))
                stack.enter_context(mock.patch.object(TTYNAME_PROC.os_test, "validate_source_root", return_value={"root": str(source)}))
                stack.enter_context(mock.patch.object(TTYNAME_PROC.os_test, "validate_dynamic_product", return_value={"root": str(product)}))
                stack.enter_context(mock.patch.object(TTYNAME_PROC.os_test, "tree_roster", return_value=[]))
                stack.enter_context(mock.patch.object(TTYNAME_PROC.os_test, "musl_oracle_identity", return_value={}))
                stack.enter_context(mock.patch.object(TTYNAME_PROC.os_test, "load_module", return_value=static))
                stack.enter_context(mock.patch.object(TTYNAME_PROC.tempfile, "mkdtemp", return_value=str(work)))
                stack.enter_context(mock.patch.object(TTYNAME_PROC, "source_binding", return_value=(source / "ttyname.c", {})))
                stack.enter_context(mock.patch.object(TTYNAME_PROC, "build_programs", return_value={}))
                stack.enter_context(mock.patch.object(TTYNAME_PROC, "run_variant", side_effect=interrupted_variant))
                with mock.patch.object(Path, "lstat", guarded_lstat):
                    with self.assertRaises(KeyboardInterrupt):
                        TTYNAME_PROC.run_profile(values)

            self.assertTrue((work / "ttyname-proc.json").is_file())

    def test_proc_teardown_failure_skips_the_post_run_tree_walk(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            (root / "usr/lib").mkdir(parents=True)
            (root / "usr/lib/libc.so").write_bytes(b"candidate")
            baseline = RUNNER.tree_roster(root)
            (root / "proc").mkdir()
            setup = RUNNER.tree_roster(root)
            control = {"root": str(root), "product_payload_before": baseline, "execution_root_after_setup": setup}
            with mock.patch.object(RUNNER, "tree_roster", side_effect=AssertionError("must not inspect mounted proc")):
                control, intact = RUNNER.retain_execution_integrity(root, "basic", control, inspect_payload=False)
            self.assertFalse(intact)
            self.assertFalse(control["product_payload"]["passed"])
            self.assertIsNone(control["product_payload"]["after"])
            private = {"mountpoint": str(root / "proc")}
            with mock.patch.object(RUNNER, "run_capture", side_effect=PermissionError("umount denied")):
                private["unmount"] = RUNNER.unmount_private_proc(private)
            self.assertEqual(private["unmount"]["status"], "EXEC_ERROR")
            self.assertFalse(RUNNER.private_proc_postwalk_safe({"mount": {"status": 0}, **private}))

    def test_host_readability_does_not_descend_into_a_live_proc_mountpoint(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            proc = root / "proc"
            (proc / "live").mkdir(parents=True)
            (root / "records").mkdir()
            (root / "records" / "report.json").write_text("{}\n")
            original_lstat = Path.lstat

            def guarded_lstat(path: Path):
                if path == proc or path.is_relative_to(proc):
                    raise AssertionError("host-readability walk entered the live procfs fixture")
                return original_lstat(path)

            with mock.patch.object(Path, "lstat", guarded_lstat):
                RUNNER.make_evidence_host_readable(root, skip_roots={proc})

    def test_exception_after_failed_proc_teardown_still_skips_the_unreported_mount(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            product, source, work = root / "product", root / "source", root / "evidence"
            product.mkdir()
            source.mkdir()
            work.mkdir()
            runtime = work / "runtime" / "basic"
            proc = runtime / "proc"
            private = {"schema": RUNNER.PRIVATE_PROC_SCHEMA, "mountpoint": str(proc),
                       "reservation": {"empty": True, "mode": 0o755}}
            devpts = {"status": 0, "target": str(runtime / "dev/pts")}
            control = {"root": str(runtime), "private_proc": private, "private_devpts": devpts,
                       "product_payload_before": [], "execution_root_after_setup": []}
            values = SimpleNamespace(timeout=1.0, header_jobs=1, dynamic_sysroot=str(product), os_test_root=source)

            def mount(destination: Path, receipt: dict[str, object]) -> None:
                self.assertEqual(destination, runtime)
                self.assertIs(receipt, private)
                receipt["mount"] = {"status": 0}

            def command(*_arguments: object) -> list[str]:
                (work / "evidence" / "basic" / "events").mkdir(parents=True)
                return ["make"]

            readable = mock.Mock()
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict(RUNNER.os.environ, {"TMPDIR": str(root)}, clear=False))
                stack.enter_context(mock.patch.object(RUNNER, "physical_work_directory", side_effect=lambda value, _label: Path(value)))
                stack.enter_context(mock.patch.object(RUNNER, "validate_dynamic_product", return_value={"root": str(product)}))
                stack.enter_context(mock.patch.object(RUNNER, "validate_source_root", return_value={"root": str(source)}))
                stack.enter_context(mock.patch.object(RUNNER.tempfile, "mkdtemp", return_value=str(work)))
                stack.enter_context(mock.patch.object(RUNNER, "tree_roster", return_value=[]))
                stack.enter_context(mock.patch.object(RUNNER, "retain_json", return_value={"path": "record"}))
                stack.enter_context(mock.patch.object(RUNNER, "stage_pristine_source", return_value={"stage": "source-stage"}))
                stack.enter_context(mock.patch.object(RUNNER, "musl_oracle_identity", return_value={}))
                stack.enter_context(mock.patch.object(RUNNER, "retain_expected_outcomes", return_value=([], {"path": "expected"})))
                stack.enter_context(mock.patch.object(RUNNER, "copied_tree"))
                stack.enter_context(mock.patch.object(RUNNER, "musl_make_command", return_value=["make"]))
                stack.enter_context(mock.patch.object(RUNNER, "run_make", return_value=(0, b"", b"")))
                stack.enter_context(mock.patch.object(RUNNER, "make_record", return_value={}))
                stack.enter_context(mock.patch.object(RUNNER, "collect_outcomes", return_value={}))
                stack.enter_context(mock.patch.object(RUNNER, "suite_passed", return_value=True))
                stack.enter_context(mock.patch.object(RUNNER, "prepare_compile_product", return_value={"root": str(work / "compiler"), "identity": {}, "copy_difference": {}, "payload": []}))
                stack.enter_context(mock.patch.object(RUNNER, "prepare_execution_root", return_value=control))
                stack.enter_context(mock.patch.object(RUNNER, "DEFAULT_SUITES", ("basic",)))
                stack.enter_context(mock.patch.object(RUNNER, "mount_private_proc", side_effect=mount))
                stack.enter_context(mock.patch.object(RUNNER, "make_command", side_effect=command))
                stack.enter_context(mock.patch.object(RUNNER, "unmount_private_proc", side_effect=OSError("proc umount denied")))
                devpts_unmount = stack.enter_context(mock.patch.object(RUNNER, "unmount_private_devpts", return_value={"status": 0}))
                stack.enter_context(mock.patch.object(RUNNER, "make_evidence_host_readable", readable))
                with self.assertRaisesRegex(OSError, "proc umount denied"):
                    RUNNER.run_profile(values)

            self.assertTrue((work / "os-test.json").is_file())
            self.assertEqual(readable.call_args.kwargs["skip_roots"], {proc})
            self.assertEqual(devpts_unmount.call_args.args[0], devpts)

    def test_private_devpts_setup_uses_a_new_instance_and_root_local_ptmx(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            with mock.patch.object(RUNNER.shutil, "which", return_value="/bin/mount"), \
                 mock.patch.object(RUNNER, "run_capture", return_value=(0, b"", b"")) as capture:
                record = RUNNER.mount_private_devpts(root)
            self.assertEqual(record["status"], 0)
            self.assertEqual(
                capture.call_args.args[0],
                ["/bin/mount", "-t", "devpts", "-o", "newinstance,ptmxmode=0666,mode=0620", "devpts", str(root / "dev/pts")],
            )
            self.assertEqual((root / "dev/ptmx").readlink(), Path("pts/ptmx"))

    def test_basic_requires_private_devpts_and_deterministic_system_file_fixtures(self) -> None:
        self.assertTrue(RUNNER.suite_needs_private_devpts("basic"))
        self.assertTrue(RUNNER.suite_needs_private_devpts("pty"))
        self.assertFalse(RUNNER.suite_needs_private_devpts("process"))
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            record = RUNNER.install_basic_runtime_fixtures(root, "basic")
            self.assertEqual(record["kind"], "basic-system-files")
            self.assertEqual((root / "dev/shm").stat().st_mode & 0o7777, 0o1777)
            self.assertEqual((root / "etc/passwd").read_text(), "root:x:0:0:root:/root:/bin/sh\n")
            self.assertEqual((root / "etc/group").read_text(), "root:x:0:\n")
            self.assertEqual((root / "etc/services").read_text(), "http 80/tcp\n")

    def test_candidate_visible_shell_launcher_preserves_shell_arguments_and_control_loader(self) -> None:
        source = RUNNER.control_shell_launcher_source()
        self.assertIn('command[0] = "/control/ld-musl-x86_64.so.1";', source)
        self.assertIn('command[1] = "/control/busybox";', source)
        self.assertIn('command[2] = "sh";', source)
        self.assertIn('for (int index = 1; index < argc; index++)', source)
        self.assertIn('command[argc + 2] = NULL;', source)
        self.assertIn('execve(command[0], command, environ);', source)

    def test_dependency_audit_rejects_host_header(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            source = root / "source"
            product = root / "product"
            (source / "case.c").parent.mkdir(parents=True)
            (product / "usr/include").mkdir(parents=True)
            (source / "case.c").write_text("int main(void) { return 0; }\n")
            (product / "usr/include/owned.h").write_text("\n")
            good = f"case.o: {source / 'case.c'} {product / 'usr/include/owned.h'}\n".encode()
            values = RUNNER.parse_dependencies(good, source, product)
            self.assertEqual(set(values), {str(source / "case.c"), str(product / "usr/include/owned.h")})
            with self.assertRaisesRegex(RUNNER.AdapterError, "escapes source"):
                RUNNER.parse_dependencies(f"case.o: {source / 'case.c'} /usr/include/stdio.h\n".encode(), source, product)

    def test_suite_gate_rejects_an_adapter_error_even_when_make_and_outcomes_exist(self) -> None:
        self.assertFalse(RUNNER.suite_passed(0, {"case.out": {}}, ["case.out"], [{"state": "adapter-error"}]))
        self.assertFalse(RUNNER.suite_passed("TIMEOUT", {"case.out": {}}, ["case.out"], []))
        self.assertFalse(RUNNER.suite_passed(0, {}, ["case.out"], []))
        self.assertFalse(RUNNER.suite_passed(0, {"unexpected.out": {}}, ["case.out"], []))
        self.assertTrue(RUNNER.suite_passed(0, {"case.out": {}}, ["case.out"], [{"state": "finished"}]))

    def test_timeout_kills_the_complete_make_process_group(self) -> None:
        status, stdout, stderr = RUNNER.run_make(["/bin/sh", "-c", "printf started; sleep 30"], 0.1)
        self.assertEqual(status, "TIMEOUT")
        self.assertEqual(stdout, b"started")
        self.assertEqual(stderr, b"")

    def test_execution_wrapper_copies_sealed_payload_before_replacing_host_path(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            source = root / "source"
            runtime = root / "runtime"
            output = source / "process/case"
            output.parent.mkdir(parents=True)
            output.write_bytes(b"owned candidate executable")
            record = RUNNER.install_execution_wrapper(output, source, runtime)
            mirrored = Path(record["runtime_path"])
            self.assertEqual(mirrored.read_bytes(), b"owned candidate executable")
            self.assertEqual(record["runtime_sha256"], hashlib.sha256(b"owned candidate executable").hexdigest())
            self.assertIn("chroot", output.read_text())
            self.assertIn("cd /work/process &&", output.read_text())
            self.assertIn("/control/ld-musl-x86_64.so.1 /control/busybox", output.read_text())
            self.assertEqual(record["runtime_cwd"], "/work/process")
            self.assertNotEqual(output.read_bytes(), mirrored.read_bytes())

    def test_make_record_binds_raw_streams_and_canonical_status(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            work = Path(temporary)
            record = RUNNER.make_record(work, "basic", "dynamic", ["make", "basic-test"], 9.0, 0, b"out\x00", b"err\n")
            self.assertEqual((work / record["stdout"]["path"]).read_bytes(), b"out\x00")
            self.assertEqual((work / record["stderr"]["path"]).read_bytes(), b"err\n")
            status = json.loads((work / record["status_record"]["path"]).read_text())
            self.assertEqual(status["suite"], "basic")
            self.assertEqual(status["side"], "dynamic")
            self.assertEqual(status["stdout"]["sha256"], hashlib.sha256(b"out\x00").hexdigest())

    def test_payload_roster_detects_a_post_execution_product_addition(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            (root / "usr/lib").mkdir(parents=True)
            (root / "usr/lib/libc.so").write_bytes(b"candidate")
            (root / "usr/include").mkdir()
            (root / "usr/include/owned.h").write_bytes(b"header")
            baseline = RUNNER.tree_roster(root)
            (root / "control").mkdir()
            setup = RUNNER.tree_roster(root)
            (root / "usr/lib/injected.so").write_bytes(b"unexpected")
            after, difference = RUNNER.product_payload_after_execution(root, baseline, setup)
            self.assertEqual(len(after), len(baseline) + 1)
            self.assertEqual(difference["unexpected"], ["usr/lib/injected.so"])
            self.assertEqual(difference["missing"], [])

    def test_control_devices_are_linux_character_nodes_with_the_expected_rdevs(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".work/x86_64") as temporary:
            root = Path(temporary)
            with mock.patch.object(RUNNER.os, "mknod") as mknod:
                RUNNER.install_control_character_devices(root)
            self.assertEqual(mknod.call_count, len(RUNNER.CONTROL_CHARACTER_DEVICES))
            for call, (_, major, minor) in zip(mknod.call_args_list, RUNNER.CONTROL_CHARACTER_DEVICES):
                _, mode, device = call.args
                self.assertTrue(mode & RUNNER.stat.S_IFCHR)
                self.assertEqual(RUNNER.os.major(device), major)
                self.assertEqual(RUNNER.os.minor(device), minor)


if __name__ == "__main__":
    unittest.main()
