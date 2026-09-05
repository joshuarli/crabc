#!/usr/bin/env python3
"""Residual installed POSIX process-control evidence stays source-bound."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CARGO = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
PROCESS_EXEC = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_exec.rs"
PROCESS_CONTEXT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_context.rs"
PROCESS_RESOURCES = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_resources.rs"
CHILD_REAPING = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "child_reaping.rs"
WAIT_EXTENSIONS = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "wait_extensions.rs"
QUALIFICATION = ROOT / "compat" / "x86_64" / "owned_dynamic_qualification.py"
RUNNER = ROOT / "compat" / "x86_64" / "run_owned_process_control.sh"
PROBE = ROOT / "compat" / "x86_64" / "owned_process_control_probe.c"
DOCUMENT = ROOT / "compat" / "x86_64" / "owned-process-control.md"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"


class OwnedProcessControlTests(unittest.TestCase):
    def test_owned_runtime_selects_the_residual_provider_leaves(self) -> None:
        cargo = CARGO.read_text(encoding="utf-8")
        self.assertIn('"x86-process-exec",', cargo)

        static_root = STATIC_ROOT.read_text(encoding="utf-8")
        for module in (
            "process_exec.rs",
            "process_exec_env.rs",
            "process_exec_path.rs",
            "process_exec_variadic.rs",
            "process_exec_execl.rs",
            "process_exec_execle.rs",
            "process_exec_execlp.rs",
            "process_context.rs",
            "child_reaping.rs",
            "wait_extensions.rs",
            "process_resources.rs",
            "posix_spawnattr_init.rs",
            "posix_spawnattr_destroy.rs",
            "posix_spawnattr_getflags.rs",
            "posix_spawnattr_getpgroup.rs",
            "posix_spawnattr_getschedparam.rs",
            "posix_spawnattr_getschedpolicy.rs",
            "posix_spawnattr_signal_fields.rs",
            "posix_spawnattr_setpgroup.rs",
            "posix_spawnattr_setschedparam.rs",
            "posix_spawnattr_setschedpolicy.rs",
        ):
            self.assertIn(f'#[path = "{module}"]', static_root)

    def test_source_mapping_keeps_fexecve_and_cancellation_boundaries_explicit(self) -> None:
        process_exec = PROCESS_EXEC.read_text(encoding="utf-8")
        self.assertIn("src/process/execve.c", process_exec)
        self.assertIn("src/process/fexecve.c", process_exec)
        self.assertIn("execveat", process_exec)
        self.assertIn("AT_EMPTY_PATH", process_exec)

        self.assertIn("src/unistd/nice.c", PROCESS_RESOURCES.read_text(encoding="utf-8"))
        context = PROCESS_CONTEXT.read_text(encoding="utf-8")
        for source in ("src/unistd/setpgid.c", "src/unistd/setpgrp.c", "src/unistd/setsid.c"):
            self.assertIn(source, context)

        reaping = CHILD_REAPING.read_text(encoding="utf-8")
        for source in ("src/process/wait.c", "src/process/waitpid.c", "src/process/waitid.c", "syscall_cp"):
            self.assertIn(source, reaping)

        extensions = WAIT_EXTENSIONS.read_text(encoding="utf-8")
        self.assertIn("src/linux/wait3.c", extensions)
        self.assertIn("src/linux/wait4.c", extensions)
        self.assertIn("cancellation-point syscall route", extensions)

    def test_probe_is_limited_to_the_residual_object_and_real_lifecycle_invariants(self) -> None:
        probe = PROBE.read_text(encoding="utf-8")
        for required in (
            "check_exec_aliases",
            "check_fexecve_seccomp",
            "check_waitpid",
            "check_waitid",
            "check_wait3",
            "check_wait4",
            "check_spawn_attributes",
            "raw_fork",
            "raw_pipe",
            "WNOWAIT",
            "ECHILD",
            "ENOSYS",
            "#include <sched.h>",
        ):
            self.assertIn(required, probe)
        self.assertIn("This workload deliberately does", probe)
        self.assertIn("not repeat either matrix", probe)
        self.assertIn("not treated as CPs", probe)

    def test_runner_binds_one_object_and_records_the_one_intentional_difference(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "RESIDUAL_SYMBOLS",
            "assert_static_symbols",
            "assert_static_elf",
            "assert_dynamic_symbols",
            "assert_dynamic_receipt_and_elf",
            '"$work/workload.o"',
            "static static-pie",
            "kernel direct",
            "fexecve-seccomp=9",
            "fexecve-seccomp=38",
            "manifest_sha256",
            "one workload object",
        ):
            self.assertIn(required, runner)

    def test_qualification_and_documentation_retain_the_composite_boundary(self) -> None:
        self.assertIn(
            '"process-control": ("run_owned_process_control.sh", None)',
            QUALIFICATION.read_text(encoding="utf-8"),
        )
        document = DOCUMENT.read_text(encoding="utf-8")
        for required in (
            "32 residual",
            "44-name composite",
            "does not execute the other 12",
            "`fexecve`'s direct",
            "`execveat(2)` `ENOSYS`",
            "ENOSYS",
            "cancellation point",
            "wait3",
            "wait4",
            "does not complete",
        ):
            self.assertIn(required, document)
        self.assertNotIn("fexecveat", document)

        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        self.assertIn("owned-process-control [DYNAMIC_SYSROOT]", dispatcher)
        self.assertIn("run_owned_process_control.sh", dispatcher)

    def test_supplied_product_escape_is_rejected_before_building(self) -> None:
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            result = subprocess.run(
                ["bash", str(RUNNER), str(ROOT)],
                env={**os.environ, "TMPDIR": temporary},
                text=True,
                capture_output=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "process-control product must be a checkout .work directory",
            result.stderr,
        )
        self.assertNotIn("evidence:", result.stdout)


if __name__ == "__main__":
    unittest.main()
