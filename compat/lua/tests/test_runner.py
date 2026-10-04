#!/usr/bin/env python3
"""Pure host-side tests for the Lua owned-sysroot runner."""

from __future__ import annotations

import concurrent.futures
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("crabc_lua_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)

DRIVER_SPEC = importlib.util.spec_from_file_location(
    "crabc_lua_static_driver", RUNNER.ROOT / "compat/x86_64/crabc_cc_static.py"
)
assert DRIVER_SPEC is not None and DRIVER_SPEC.loader is not None
DRIVER = importlib.util.module_from_spec(DRIVER_SPEC)
sys.modules[DRIVER_SPEC.name] = DRIVER
DRIVER_SPEC.loader.exec_module(DRIVER)


class ManifestTests(unittest.TestCase):
    def test_lua_pin_is_complete_and_uses_the_expected_release(self) -> None:
        manifest = RUNNER.load_manifest()
        lua = manifest["lua"]
        self.assertEqual(lua["version"], "5.4.8")
        self.assertEqual(lua["archive_root"], "lua-5.4.8")
        self.assertEqual(
            lua["sha256"],
            "4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae",
        )
        self.assertEqual(manifest["musl"]["version"], "1.2.6")

    def test_source_lists_are_nonempty_and_do_not_repeat_or_include_mains(self) -> None:
        sources = (*RUNNER.CORE_SOURCES, *RUNNER.LIB_SOURCES)
        self.assertEqual(len(sources), len(set(sources)))
        self.assertNotIn("lua.c", sources)
        self.assertNotIn("luac.c", sources)
        self.assertGreater(len(RUNNER.CORE_SOURCES), 10)
        self.assertGreater(len(RUNNER.LIB_SOURCES), 10)

    def test_safe_extract_accepts_the_archive_root_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "lua.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                directory = tarfile.TarInfo("lua-5.4.8")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                stream.addfile(directory)
                source = tarfile.TarInfo("lua-5.4.8/src/lua.c")
                contents = b"int main(void) { return 0; }\n"
                source.size = len(contents)
                source.mode = 0o644
                stream.addfile(source, io.BytesIO(contents))
            extracted = RUNNER.safe_extract(archive, root / "out", "lua-5.4.8")
            self.assertEqual((extracted / "src/lua.c").read_bytes(), contents)


class ElfAndDiagnosticTests(unittest.TestCase):
    def test_interpreter_patch_preserves_bytes_outside_interp(self) -> None:
        binary = bytearray(320)
        binary[:4] = b"\x7fELF"
        binary[4] = 2
        binary[5] = 1
        binary[18:20] = (183).to_bytes(2, "little")
        binary[32:40] = (64).to_bytes(8, "little")
        binary[54:56] = (56).to_bytes(2, "little")
        binary[56:58] = (1).to_bytes(2, "little")
        binary[64:68] = (3).to_bytes(4, "little")
        binary[72:80] = (192).to_bytes(8, "little")
        binary[96:104] = (60).to_bytes(8, "little")
        binary[192:252] = b"/workspace/candidate/lib/ld.so\0".ljust(60, b"\0")
        patched = RUNNER.patch_interpreter_bytes(bytes(binary), "/opt/musl-1.2.6/lib/ld-musl-aarch64.so.1")
        self.assertEqual(patched[:192], bytes(binary[:192]))
        self.assertIn(b"/opt/musl-1.2.6", patched[192:252])
        self.assertEqual(patched[252:], bytes(binary[252:]))

    def test_interpreter_patch_rejects_wrong_machine_and_overlong_path(self) -> None:
        binary = bytearray(256)
        binary[:4] = b"\x7fELF"
        binary[4] = 2
        binary[5] = 1
        binary[18:20] = (62).to_bytes(2, "little")
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.patch_interpreter_bytes(bytes(binary), "/tmp/ld")

    def test_syscall_summary_counts_calls_and_errors(self) -> None:
        summary = RUNNER.syscall_summary(
            "123 openat(AT_FDCWD, \"/x\", O_RDONLY) = 3\n"
            "123 close(3) = 0\n"
            "124 openat(AT_FDCWD, \"/missing\", O_RDONLY) = -1 ENOENT\n"
        )
        self.assertEqual(summary["total_calls"], 3)
        self.assertEqual(summary["calls"], {"close": 1, "openat": 2})
        self.assertEqual(summary["errors"], {"openat": 1})


class FixtureAndEnvironmentTests(unittest.TestCase):
    def test_fixture_contract_markers_are_present(self) -> None:
        for name in ("header_probe.c", "crabc_probe.c", "crabc_fail.c", "static_preload.c", "exercise.lua"):
            self.assertTrue((RUNNER.FIXTURES / name).is_file(), name)
        source = (RUNNER.FIXTURES / "exercise.lua").read_text(encoding="utf-8")
        for marker in (
            "require(\"crabc_probe\")",
            "crabc_missing",
            "crabc_fail",
            "CRABC_LUA_DYNAMIC_MODULES",
            "package.preload",
            "maps-ready",
            "utf8",
            "io.popen",
        ):
            self.assertIn(marker, source)

    def test_sanitized_environment_removes_runtime_path_overrides(self) -> None:
        prior = dict(os.environ)
        try:
            os.environ.update({"LD_LIBRARY_PATH": "/bad", "LUA_PATH": "/bad", "CRABC_LUA_ENV": "bad"})
            environment = RUNNER.sanitize_environment()
        finally:
            for key in tuple(os.environ):
                if key not in prior:
                    del os.environ[key]
            os.environ.update(prior)
        self.assertNotIn("LD_LIBRARY_PATH", environment)
        self.assertNotIn("LUA_PATH", environment)
        self.assertNotIn("CRABC_LUA_ENV", environment)
        self.assertEqual(environment["LC_ALL"], "C")


class NativeStaticContracts(unittest.TestCase):
    """Executable host contracts for the native static lane's hard boundaries."""

    scratch_root = RUNNER.ROOT / ".work" / "lua-runner-host-tests"

    def setUp(self) -> None:
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.temporary = Path(tempfile.mkdtemp(prefix="lua-", dir=self.scratch_root))
        self.addCleanup(self.cleanup)

    def cleanup(self) -> None:
        if self.temporary.exists() and not self.temporary.is_symlink():
            shutil.rmtree(self.temporary, ignore_errors=True)

    def assert_stopped(self, pid: int, message: str) -> None:
        status = Path(f"/proc/{pid}/stat")
        for _ in range(100):
            if not status.exists():
                return
            try:
                state = status.read_text(encoding="utf-8").rsplit(")", 1)[1].split()[0]
            except (IndexError, OSError):
                return
            if state == "Z":
                return
            time.sleep(0.02)
        self.fail(message)

    def test_x86_static_defaults_cover_et_exec_and_static_pie(self) -> None:
        parsed = RUNNER.parse_args(["--target", "x86_64-static"])
        modes = RUNNER.selected_static_modes(parsed.mode)
        self.assertEqual([mode.identifier for mode in modes], ["static-et-exec", "static-pie"])
        self.assertEqual(parsed.report, RUNNER.DEFAULT_X86_STATIC_REPORT)
        selected = RUNNER.parse_args(["--target", "x86_64-static", "--mode", "static"])
        self.assertEqual([mode.identifier for mode in RUNNER.selected_static_modes(selected.mode)], ["static-et-exec"])

    def test_x86_static_refuses_unbounded_worker_or_timeout_configuration(self) -> None:
        for arguments in (
            ["--target", "x86_64-static", "--jobs", "0"],
            ["--target", "x86_64-static", "--jobs", "9"],
            ["--target", "x86_64-static", "--timeout", "nan"],
            ["--target", "x86_64-static", "--timeout", "301"],
        ):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    RUNNER.parse_args(arguments)

    def test_debug_source_profile_is_native_x86_only(self) -> None:
        parsed = RUNNER.parse_args(["--target", "x86_64-static", "--build-profile", "debug"])
        self.assertEqual(parsed.build_profile, "debug")
        self.assertIn("-O0", RUNNER.static_compiler_flags(parsed.build_profile))
        self.assertNotIn("-O2", RUNNER.static_compiler_flags(parsed.build_profile))
        self.assertEqual(parsed.report, parsed.work_root / "debug-report.json")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            RUNNER.parse_args(["--build-profile", "debug"])

    def test_timeout_limit_applies_to_both_runner_targets(self) -> None:
        for target in ("aarch64-dynamic", "x86_64-static"):
            for timeout in ("nan", "inf", "-inf", "0", "301"):
                with self.subTest(target=target, timeout=timeout), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        RUNNER.parse_args(["--target", target, "--timeout", timeout])
            self.assertEqual(
                RUNNER.parse_args(["--target", target, "--timeout", "300"]).timeout,
                300.0,
            )

    def test_x86_dispatcher_rejects_arguments_before_starting_a_container(self) -> None:
        for command in (
            "lua-static-source-build",
            "lua-dynamic-source-build",
            "lua-source-build-admission",
        ):
            result = subprocess.run(
                ["bash", str(RUNNER.ROOT / "scripts/dev-x86_64.sh"), command, "unexpected"],
                cwd=RUNNER.ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn(f"{command} takes".encode(), result.stderr)

    def test_x86_dispatcher_expands_bounded_knobs_into_the_container_argv(self) -> None:
        binaries = self.temporary / "bin"
        binaries.mkdir()
        captured = self.temporary / "docker-run.argv"
        docker = binaries / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = image ] && [ \"$2\" = inspect ]; then\n"
            "  for argument in \"$@\"; do\n"
            "    if [ \"$argument\" = --format ]; then printf '%s\\n' linux/amd64; exit 0; fi\n"
            "  done\n"
            "  exit 0\n"
            "fi\n"
            "if [ \"$1\" = run ]; then printf '%s\\n' \"$@\" >\"$CAPTURED_DOCKER_ARGV\"; exit 0; fi\n"
            "exit 99\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        environment = dict(os.environ)
        environment.update(
            {
                "PATH": f"{binaries}:/usr/bin:/bin",
                "CAPTURED_DOCKER_ARGV": str(captured),
                "CRABC_X86_64_LUA_JOBS": "3",
                "CRABC_X86_64_LUA_TIMEOUT": "7",
            }
        )
        for command, script, expected_capabilities in (
            ("lua-static-source-build", "run_x86_static_dispatch.py", []),
            ("lua-dynamic-source-build", "run_x86_dynamic.py", ["--cap-add=SYS_CHROOT"]),
        ):
            result = subprocess.run(
                ["bash", str(RUNNER.ROOT / "scripts/dev-x86_64.sh"), command],
                cwd=RUNNER.ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            arguments = captured.read_text(encoding="utf-8").splitlines()
            self.assertIn(f"/workspace/compat/lua/{script}", arguments)
            self.assertEqual(arguments[arguments.index("--jobs") + 1], "3")
            self.assertEqual(arguments[arguments.index("--timeout") + 1], "7")
            self.assertEqual(
                [argument for argument in arguments if argument.startswith("--cap-add")],
                expected_capabilities,
            )
            self.assertNotIn("--privileged", arguments)
            self.assertFalse(any(argument.startswith("--security-opt") for argument in arguments))

    def test_x86_work_root_rejects_external_and_symlinked_state(self) -> None:
        external = RUNNER.ROOT.parent / "outside-lua-work-root"
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.native_work_root(external)
        accepted = RUNNER.native_work_root(self.temporary / "accepted")
        self.assertTrue(accepted.is_relative_to((RUNNER.ROOT / ".work").resolve()))
        link = self.temporary / "escape"
        os.symlink(external, link)
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.native_work_root(link / "child")
        cache = accepted / "cache"
        os.symlink("/dev/null", cache)
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.native_source_cache(accepted)

    def test_static_elf_mode_and_dynamic_markers_are_rejected(self) -> None:
        valid_header = "  Type:                              EXEC (Executable file)\n  Machine:                           Advanced Micro Devices X86-64\n"
        RUNNER.validate_static_elf_facts(
            header=valid_header,
            program_headers="LOAD\n",
            dynamic="There is no dynamic section in this file.\n",
            relocations="There are no relocations in this file.\n",
            mode=RUNNER.STATIC_ET_EXEC,
            label="fixture",
        )
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.validate_static_elf_facts(
                header=valid_header,
                program_headers="INTERP\n",
                dynamic="There is no dynamic section in this file.\n",
                relocations="There are no relocations in this file.\n",
                mode=RUNNER.STATIC_ET_EXEC,
                label="fixture",
            )
        with self.assertRaises(RUNNER.RunnerError):
            RUNNER.validate_static_elf_facts(
                header=valid_header,
                program_headers="LOAD\n",
                dynamic="0x0000000000000001 (NEEDED) Shared library: [libc.so]\n",
                relocations="There are no relocations in this file.\n",
                mode=RUNNER.STATIC_ET_EXEC,
                label="fixture",
            )

    def static_receipt_fixture(self, mode: RUNNER.StaticLuaMode, output_name: str = "candidate/lua") -> dict[str, object]:
        work = self.temporary / mode.identifier
        library = work / "sysroot/usr/lib"
        library.mkdir(parents=True)
        runtime = [library / name for name in (mode.crt_object, "crti.o", "libc.a", "libcrabc-builtins.a", "crtn.o")]
        application = work / "lua.o"
        linker = work / "ld.lld"
        output = work / output_name
        output.parent.mkdir(parents=True, exist_ok=True)
        for path in (*runtime, application, linker, output):
            path.write_bytes(path.name.encode())
        receipt = work / "receipts/lua.json"
        receipt.parent.mkdir(exist_ok=True)
        receipt.with_suffix(".map").write_text("owned Lua link\n", encoding="utf-8")
        receipt.with_suffix(".trace").write_text(
            "\n".join(str(path) for path in (*runtime, application)) + "\n", encoding="utf-8"
        )
        # Use the producer's real serialization with the runner's relative argv.
        with contextlib.chdir(work):
            DRIVER.write_link_receipt(
                work / "sysroot", DRIVER.static_mode(mode.driver_id), [application],
                Path(output_name), linker, Path("receipts/lua.json"),
                Path("receipts/lua.map"), Path("receipts/lua.trace"),
            )
        return {
            "sysroot": work / "sysroot", "mode": mode, "objects": [application],
            "output": output, "receipt": receipt,
        }

    def test_static_receipt_uses_nested_receipt_directory_anchor(self) -> None:
        for mode in (RUNNER.STATIC_ET_EXEC, RUNNER.STATIC_PIE):
            with self.subTest(mode=mode.identifier):
                arguments = self.static_receipt_fixture(mode)
                self.assertEqual(RUNNER.audit_static_link_receipt(**arguments)["status"], "passed")

    def test_static_receipt_accepts_output_below_receipt_directory(self) -> None:
        arguments = self.static_receipt_fixture(RUNNER.STATIC_ET_EXEC, "receipts/program/lua")
        self.assertEqual(RUNNER.audit_static_link_receipt(**arguments)["status"], "passed")

    def test_static_receipt_rejects_forged_paths_hashes_and_inputs(self) -> None:
        arguments = self.static_receipt_fixture(RUNNER.STATIC_ET_EXEC)
        receipt = arguments["receipt"]
        assert isinstance(receipt, Path)
        original = json.loads(receipt.read_text(encoding="utf-8"))
        for field in ("output", "map", "trace"):
            for key, value in (
                ("path", "../candidate/lua"),
                ("path", str(receipt.parent / "other")),
                ("path", "candidate/lua" if field == "output" else f"receipts/lua.{field}"),
                ("sha256", "0" * 64),
            ):
                with self.subTest(field=field, key=key, value=value):
                    forged = json.loads(json.dumps(original))
                    forged[field][key] = value
                    receipt.write_text(json.dumps(forged), encoding="utf-8")
                    with self.assertRaisesRegex(RUNNER.RunnerError, f"{field} receipt drifted"):
                        RUNNER.audit_static_link_receipt(**arguments)
        for index in (0, len(original["input_receipts"]) - 1):
            with self.subTest(input_index=index):
                forged = json.loads(json.dumps(original))
                forged["input_receipts"][index]["sha256"] = "0" * 64
                receipt.write_text(json.dumps(forged), encoding="utf-8")
                with self.assertRaisesRegex(RUNNER.RunnerError, "receipt drifted"):
                    RUNNER.audit_static_link_receipt(**arguments)
        receipt.write_text(json.dumps(original), encoding="utf-8")
        trace = receipt.with_suffix(".trace")
        trace.write_text(trace.read_text(encoding="utf-8") + "/unowned/input.o\n", encoding="utf-8")
        original["trace"]["sha256"] = RUNNER.sha256_file(trace)
        receipt.write_text(json.dumps(original), encoding="utf-8")
        with self.assertRaisesRegex(RUNNER.RunnerError, "trace consumed an unowned input"):
            RUNNER.audit_static_link_receipt(**arguments)

    def test_static_execution_protocol_has_no_loader_path_and_selects_preloads(self) -> None:
        fixture = self.temporary / "fixture"
        fixture.mkdir()
        script = self.temporary / "workload.lua"
        script.write_text("unused", encoding="utf-8")
        program = (
            "import os, sys; "
            "assert os.environ['CRABC_LUA_DYNAMIC_MODULES'] == '0'; "
            "assert 'LD_LIBRARY_PATH' not in os.environ; "
            "assert len(sys.argv) == 4; "
            "print('static-preload-protocol-ok')"
        )
        result = RUNNER.run_static_lua(
            [sys.executable, "-c", program],
            script,
            self.temporary,
            fixture,
            self.temporary / "state",
            2.0,
        )
        self.assertEqual(result.status, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, b"static-preload-protocol-ok\n")

    def test_core_limit_is_inherited_without_preexec_child_setup(self) -> None:
        RUNNER.disable_core_dump_inheritance()
        program = (
            "import resource; "
            "print(resource.getrlimit(resource.RLIMIT_CORE)[0])"
        )
        result = RUNNER.command_record([sys.executable, "-c", program], timeout=2.0)
        self.assertEqual(result["status"], 0)
        stdout = result["stdout"]
        assert isinstance(stdout, dict)
        self.assertEqual(stdout["text"], "0\n")

    def test_threaded_command_launch_uses_no_preexec_callback(self) -> None:
        observed: list[dict[str, object]] = []
        lock = threading.Lock()
        original = RUNNER.subprocess.Popen

        def capture(*arguments: object, **keywords: object) -> subprocess.Popen[bytes]:
            with lock:
                observed.append(dict(keywords))
            return original(*arguments, **keywords)

        RUNNER.subprocess.Popen = capture
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                records = list(
                    executor.map(
                        lambda _: RUNNER.command_record([sys.executable, "-c", "print('threaded-ok')"], timeout=2.0),
                        range(4),
                    )
                )
        finally:
            RUNNER.subprocess.Popen = original
        self.assertEqual([record["status"] for record in records], [0, 0, 0, 0])
        self.assertEqual(len(observed), 4)
        self.assertTrue(all("preexec_fn" not in keywords for keywords in observed))

    def test_timeout_and_clean_leader_exit_reap_owned_descendants(self) -> None:
        timeout_program = (
            "import subprocess, sys, time; "
            "child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
            "print(child.pid, flush=True); time.sleep(60)"
        )
        timeout = RUNNER.command_record([sys.executable, "-c", timeout_program], timeout=0.2)
        self.assertEqual(timeout["status"], "TIMEOUT")
        timeout_stdout = timeout["stdout"]
        assert isinstance(timeout_stdout, dict)
        self.assert_stopped(int(str(timeout_stdout["text"]).strip()), "timeout left a descendant alive")

        detached_program = (
            "import subprocess, sys; "
            "child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); print(child.pid, flush=True)"
        )
        leak = RUNNER.command_record([sys.executable, "-c", detached_program], timeout=2.0)
        self.assertEqual(leak["status"], "PROCESS_GROUP_LEAK")
        leak_stdout = leak["stdout"]
        assert isinstance(leak_stdout, dict)
        self.assert_stopped(int(str(leak_stdout["text"]).strip()), "clean leader exit leaked a descendant")


if __name__ == "__main__":
    unittest.main()
