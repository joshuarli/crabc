#!/usr/bin/env python3
"""Contracts for the opt-in native x86 direct process-exec provider."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class X86LibcProcessExecTests(unittest.TestCase):
    def test_provider_remains_an_explicit_process_image_replacement_slice(
        self,
    ) -> None:
        cargo = (ROOT / "libc" / "Cargo.toml").read_text(encoding="utf-8")
        static_root = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
        ).read_text(encoding="utf-8")
        direct = (
            ROOT / "libc" / "src" / "c_abi" / "x86_64" / "process_exec.rs"
        ).read_text(encoding="utf-8")
        environment = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "process_exec_env.rs"
        ).read_text(encoding="utf-8")
        path = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "process_exec_path.rs"
        ).read_text(encoding="utf-8")
        variadic = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "process_exec_variadic.rs"
        ).read_text(encoding="utf-8")
        execl = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "process_exec_execl.rs"
        ).read_text(encoding="utf-8")
        execle = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "process_exec_execle.rs"
        ).read_text(encoding="utf-8")
        execlp = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "process_exec_execlp.rs"
        ).read_text(encoding="utf-8")

        self.assertIn("x86-process-exec = []", cargo)
        for module in (
            "process_exec.rs",
            "process_exec_env.rs",
            "process_exec_path.rs",
            "process_exec_variadic.rs",
            "process_exec_execl.rs",
            "process_exec_execle.rs",
            "process_exec_execlp.rs",
        ):
            self.assertIn('#[cfg(feature = "x86-process-exec")]', static_root)
            self.assertIn(f'#[path = "{module}"]', static_root)
        self.assertIn(
            "ordinary static `execve`/`fexecve` consumers avoid", static_root
        )
        self.assertIn("the variadic forms add mmap", static_root)

        for required in (
            "pinned musl 1.2.6",
            "SYS_EXECVE",
            "SYS_EXECVEAT",
            "AT_EMPTY_PATH",
            "procfs fallback",
            "or select fork, vfork, clone",
        ):
            self.assertIn(required, direct)
        self.assertIn("use super::{c_status, raw_syscall};", direct)
        self.assertNotIn("use super::{environment", direct)
        self.assertNotIn("process_exec_variadic", direct)

        for required in (
            "execv",
            "current_environment",
            "__environ",
            "1,048,576-entry `getenv` lookup",
            "mutation contract",
        ):
            self.assertIn(required, environment)
        self.assertNotIn("raw_syscall", environment)
        self.assertNotIn("process_exec_variadic", environment)

        for required in (
            "execvp",
            "__execvpe",
            ".weak execvpe",
            ".set execvpe, __execvpe",
            'DEFAULT_PATH: &[u8] = b"/usr/local/bin:/bin:/usr/bin\\0"',
            "NAME_MAX",
            "PATH_MAX",
            "environment::getenv",
        ):
            self.assertIn(required, path)
        for excluded in ("SYS_MMAP", "variadic_argv"):
            self.assertNotIn(excluded, path)

        for required in (
            "ArgumentVector",
            "variadic_argv",
            "SYS_MMAP",
            "SYS_MUNMAP",
            "checked_add",
            "checked_mul",
            "E2BIG",
        ):
            self.assertIn(required, variadic)
        self.assertIn("pub unsafe extern \"C\" fn execl", execl)
        self.assertIn("process_exec_env::current_environment", execl)
        self.assertIn("pub unsafe extern \"C\" fn execle", execle)
        self.assertNotIn("process_exec_env", execle)
        self.assertIn("pub unsafe extern \"C\" fn execlp", execlp)
        self.assertIn("process_exec_path::execvp", execlp)

    def test_native_evidence_keeps_child_execution_and_the_no_procfd_rule(self) -> None:
        header_runner = (
            ROOT / "compat" / "x86_64" / "run_process_exec_header_abi.sh"
        ).read_text(encoding="utf-8")
        artifact_runner = (
            ROOT / "compat" / "x86_64" / "run_libc_process_exec.sh"
        ).read_text(encoding="utf-8")
        probe = (
            ROOT / "compat" / "x86_64" / "libc_process_exec_probe.c"
        ).read_text(encoding="utf-8")

        for required in (
            "execvpe",
            "fexecve",
            "strict-scrubbed",
            "retained a mangled",
            "unmangled C linkage",
        ):
            self.assertIn(required, header_runner)
        for required in (
            "x86-process-exec",
            "execve=59",
            "execveat=322",
            "weak execvpe",
            "execve-only",
            "fexecve-only",
            "environment closure",
            "without --gc-sections",
            "1,048,576-entry `getenv` lookup",
            "DEFAULT_PATH",
            "strong execvpe override",
            "stack-spilled",
        ):
            self.assertIn(required, artifact_runner)
        for required in (
            "raw-forked child",
            "check_direct_failure_errno",
            "check_empty_path_leading",
            "check_empty_path_interior",
            "check_empty_path_trailing",
            "check_default_path",
            "check_enoexec_is_terminal",
            "check_eacces_precedence",
            "check_enoexec_after_eacces_is_terminal",
            "check_path_name_bounds_and_slash_bypass",
            "check_fexecve_enosys",
            "SECCOMP_RET_ERRNO",
            "FIXTURE_ENOSYS",
            "CRABC_PROCESS_EXEC_EXECVE_ONLY",
            "CRABC_PROCESS_EXEC_FEXECVE_ONLY",
            "CRABC_PROCESS_EXEC_CANDIDATE",
            "execvpe",
            "fexecve",
            "stack-word-four",
        ):
            self.assertIn(required, probe)


if __name__ == "__main__":
    unittest.main()
