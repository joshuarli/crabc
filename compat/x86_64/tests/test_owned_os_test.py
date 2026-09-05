#!/usr/bin/env python3
"""Pure contract tests for the owned native os-test adapter."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shlex
import sys
import tempfile
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
