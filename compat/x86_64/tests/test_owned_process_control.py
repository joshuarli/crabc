#!/usr/bin/env python3
"""Residual installed POSIX process-control evidence stays source-bound."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[3]
CARGO = ROOT / "libc" / "Cargo.toml"
COVERAGE = ROOT / "compat" / "crabc-rs" / "coverage.toml"
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
            "assert_static_receipt_and_elf",
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

    def test_static_links_bind_the_object_to_the_sealed_runtime_receipt(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "--link-receipt",
            "assert_static_receipt_and_elf",
            "assert_static_receipt_tampering_rejected",
            "assert_static_manifest_tampering_rejected",
            "manifest/runtime identity",
            "runtime or workload input receipt drifted",
            "output identity drifted",
            "manifest/runtime identity drifted: libc",
            "owned_link_contract",
            "input_receipts",
        ):
            self.assertIn(required, runner)

        # The manifest mutation must be tested only after both receipt paths
        # have been rebound to the copied product and that copy has passed.
        self.assertIn(
            "forged_trace.write_bytes(rebind(source_trace.read_bytes()))",
            runner,
        )
        self.assertIn(
            "field.replace(str(source_product), str(forged_product))",
            runner,
        )
        self.assertLess(
            runner.index('assert_static_receipt_and_elf "$forged_product"'),
            runner.index("PY_MANIFEST"),
        )

    def test_residual_and_reused_spellings_partition_the_frozen_control_roster(self) -> None:
        coverage = tomllib.loads(COVERAGE.read_text(encoding="utf-8"))
        control = next(
            row["symbols"] for row in coverage["capability"] if row["id"] == "process.control"
        )
        runner = RUNNER.read_text(encoding="utf-8")
        match = re.search(r"^readonly RESIDUAL_SYMBOLS='([^']*)'$", runner, re.MULTILINE)
        self.assertIsNotNone(match)
        residual_items = match.group(1).split() if match else []
        residual = frozenset(residual_items)
        reused = frozenset((
            "clone",
            "daemon",
            "fork",
            "posix_spawn",
            "posix_spawnp",
            "vfork",
            "posix_spawn_file_actions_addchdir_np",
            "posix_spawn_file_actions_addclose",
            "posix_spawn_file_actions_adddup2",
            "posix_spawn_file_actions_addfchdir_np",
            "posix_spawn_file_actions_addopen",
            "posix_spawn_file_actions_destroy",
            "posix_spawn_file_actions_init",
        ))
        self.assertEqual(len(control), 44)
        self.assertEqual(len(residual_items), len(residual))
        self.assertEqual(len(residual), 31)
        self.assertEqual(len(reused), 13)
        self.assertTrue(residual.isdisjoint(reused))
        self.assertEqual(residual | reused, frozenset(control))

    def test_qualification_and_documentation_retain_the_composite_boundary(self) -> None:
        self.assertIn(
            '"process-control": ("run_owned_process_control.sh", None)',
            QUALIFICATION.read_text(encoding="utf-8"),
        )
        document = DOCUMENT.read_text(encoding="utf-8")
        for required in (
            "31 residual",
            "44-name composite",
            "does not execute the other 13",
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
        self.assertIn("owned-process-control [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]", dispatcher)
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

    def test_static_replay_parser_rejects_invalid_arguments_before_output(self) -> None:
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        cases = (
            ["--static-sysroot"],
            ["--static-sysroot", ""],
            [""],
            ["--static-sysroot", "--unknown"],
            ["--static-sysroot", "-x"],
            ["--unknown"],
            ["-x"],
            ["--static-sysroot", str(ROOT), "--static-sysroot", str(ROOT)],
            [str(ROOT), str(ROOT)],
            [str(ROOT), ""],
            ["--static-sysroot", str(ROOT), ""],
        )
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        ["bash", str(RUNNER), *arguments], cwd=ROOT,
                        env={**os.environ, "TMPDIR": temporary},
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr,
                        f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n")
                    self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_static_replay_rejects_ambient_or_incomplete_products_before_building(self) -> None:
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            incomplete = Path(temporary) / "incomplete"
            incomplete.mkdir()
            for product in (ROOT, incomplete):
                with self.subTest(product=product):
                    result = subprocess.run(
                        ["bash", str(RUNNER), "--static-sysroot", str(product)], cwd=ROOT,
                        env={**os.environ, "TMPDIR": temporary}, capture_output=True, text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(list(Path(temporary).iterdir()), [incomplete])

    def test_supplied_static_selection_preserves_existing_dynamic_only_route(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        for required in (
            "dynamic_was_supplied=0",
            'elif [ "$dynamic_was_supplied" -eq 0 ]; then',
            'static_product="$provided_static"',
            '"$static_product/bin/crabc-cc" "-$mode"',
            'assert_static_receipt_and_elf "$static_product"',
            'assert_static_receipt_tampering_rejected "$static_product"',
            'assert_static_manifest_tampering_rejected "$static_product"',
        ):
            self.assertIn(required, runner)

    def test_process_capture_retains_actual_status_and_failure_behavior(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        match = re.search(r"^run_in_root\(\) \{\n.*?^\}", runner, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match)
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            work = Path(temporary)
            for status in (0, 7, 124):
                with self.subTest(status=status):
                    child = work / f"chroot-{status}"
                    child.write_text(f"#!/bin/sh\nprintf 'raw stdout\\n'\nprintf 'raw stderr\\n' >&2\nexit {status}\n")
                    child.chmod(0o755)
                    output = work / f"result-{status}.stdout"
                    body = ("set -euo pipefail\nCHROOT=$1\n" + match.group(0)
                            + '\nrun_in_root "$2" "$3" /consumer\n')
                    result = subprocess.run(
                        ["bash", "-c", body, "process-capture", str(child), str(work), str(output)],
                        cwd=ROOT, capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, status)
                    self.assertEqual(output.read_text(), "raw stdout\n")
                    self.assertEqual(output.with_suffix(".stderr").read_text(), "raw stderr\n")
                    self.assertEqual(output.with_suffix(".status").read_text(), f"{status}\n")


if __name__ == "__main__":
    unittest.main()
