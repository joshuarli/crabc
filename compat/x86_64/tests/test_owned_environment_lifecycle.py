#!/usr/bin/env python3
"""Installed environment lifecycle qualification stays source-bound."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
DOCUMENT = ROOT / "compat/x86_64/owned-environment-lifecycle.md"
PROBE = ROOT / "compat/x86_64/owned_environment_lifecycle_probe.c"
RUNNER = ROOT / "compat/x86_64/run_owned_environment_lifecycle.sh"
RUNTIME = ROOT / "libc/src/c_abi/x86_64/environment_runtime.rs"
CATALOG = ROOT / "compat/x86_64/owned-posix-runtime-catalog.toml"
QUALIFICATION = ROOT / "compat/x86_64/owned_dynamic_qualification.py"
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"


class OwnedEnvironmentLifecycleTests(unittest.TestCase):
    def assert_parser_usage(self, *arguments: str) -> None:
        temporary_root = ROOT / ".work" / "x86_64" / "tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-environment-lifecycle-parser.", dir=temporary_root
        ) as temporary:
            tools = Path(temporary) / "tools"
            tools.mkdir()
            python = tools / "python3"
            python.write_text("#!/bin/sh\nexit 79\n", encoding="utf-8")
            python.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = f"{tools}{os.pathsep}{environment['PATH']}"
            result = subprocess.run(
                ["bash", str(RUNNER), *arguments],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
        )

    def test_installed_lifecycle_matrix_is_musl_shaped_and_caller_serialized(
        self,
    ) -> None:
        document = DOCUMENT.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        runtime = RUNTIME.read_text(encoding="utf-8")
        catalog = CATALOG.read_text(encoding="utf-8")

        for source in (
            "src/env/__environ.c",
            "src/env/getenv.c",
            "src/env/setenv.c",
            "src/env/putenv.c",
            "src/env/unsetenv.c",
            "src/env/clearenv.c",
        ):
            self.assertIn(source, document)
            self.assertIn(source, runtime)
        for phrase in (
            "oldenv",
            "__env_rm_add",
            "caller-owned `putenv`",
            "borrowed",
            "fork",
            "exec",
            "posix_spawn",
            "concurrent mutation",
            "global-state-composition",
        ):
            self.assertIn(phrase, document)
        for required in (
            "check_replacement_removal_clear",
            "check_direct_environ_and_borrowed_value",
            "check_allocation_failure_environment_unchanged",
            "deny_allocation_growth",
            "SYS_mmap",
            "SYS_brk",
            "CRABC_SECCOMP_RET_ERRNO | ENOMEM",
            "CRABC_FAILURE_VALUE_BYTES",
            "sizeof(long) == 8 && sizeof(uintptr_t) == sizeof(void *)",
            "prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL)",
            "(long)(uintptr_t)&program",
            "run_fork_snapshot",
            "run_exec_environment",
            "run_spawn_environment",
            '"exec-child"',
            '"spawn-child"',
            "posix_spawn",
            "waitpid",
            "caller serializes every environment access",
        ):
            self.assertIn(required, probe)
        self.assertNotIn("pthread_create", probe)
        for required in (
            "crabc-cc-dynamic",
            "workload.o",
            "sha256sum",
            "--link-receipt",
            "validate_sealed_link",
            "from owned_posix_product_evidence import validate_link",
            "link-identities.json",
            ".stdout.status",
            "assert_retained_identity_tampering_rejected",
            'record["workload_sha256"] = "0" * 64',
            "retained link identity differs from shared validator",
            "allocation-failure",
            "fixture-seccomp ENOMEM",
            "static-pie",
            "--dynamic-pie",
            "--dynamic-$mode",
            "for mode in pie non-pie",
            "/lib/ld-crabc-x86_64.so.1",
            "chroot",
            "cmp",
            "provided_dynamic",
            "owned-environment-lifecycle",
        ):
            self.assertIn(required, runner)
        self.assertIn("environment-lifecycle", catalog)
        self.assertIn("run_owned_environment_lifecycle.sh", catalog)

    def test_runner_retains_shared_validator_identity_and_rejects_its_tamper(
        self,
    ) -> None:
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertLess(
            runner.index("validate_sealed_link \"$static_product\""),
            runner.index('compare_oracle "$mode"'),
        )
        self.assertLess(
            runner.index('validate_sealed_link "$installed"'),
            runner.index('compare_oracle "dynamic-$mode-kernel"'),
        )
        self.assertLess(
            runner.rindex("\nretain_link_identities\n"),
            runner.rindex("\nassert_retained_identity_tampering_rejected"),
        )

    def test_static_replay_parser_rejects_a_missing_sysroot_path(self) -> None:
        self.assert_parser_usage("--static-sysroot")

    def test_static_replay_parser_rejects_ambiguous_supplied_products(self) -> None:
        for label, arguments in (
            ("empty static", ("--static-sysroot", "")),
            ("empty dynamic", ("",)),
            ("option static", ("--static-sysroot", "--not-a-sysroot")),
            ("duplicate static", ("--static-sysroot", "/one", "--static-sysroot", "/two")),
            ("duplicate dynamic", ("/one", "/two")),
        ):
            with self.subTest(label=label):
                self.assert_parser_usage(*arguments)

    def test_static_replay_parser_keeps_one_dynamic_positional_product(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")

        for required in (
            "provided_static=''",
            "provided_dynamic=''",
            "static_was_supplied=0",
            "dynamic_was_supplied=0",
            "--static-sysroot)",
            "[ \"$static_was_supplied\" -eq 0 ] || usage",
            "[ \"$dynamic_was_supplied\" -eq 0 ] || usage",
            "case \"$2\" in --*) usage ;; esac",
            "owned environment-lifecycle {name} product must be a checkout .work directory",
            "elif [ \"$dynamic_was_supplied\" -eq 0 ]; then",
            'static_product="$provided_static"',
        ):
            self.assertIn(required, runner)

    def test_dynamic_case_and_dispatch_remain_registered(self) -> None:
        qualification = QUALIFICATION.read_text(encoding="utf-8")
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        self.assertIn(
            '"environment-lifecycle": ("run_owned_environment_lifecycle.sh", None)',
            qualification,
        )
        self.assertIn("owned-environment-lifecycle", dispatcher)
        self.assertIn("run_owned_environment_lifecycle.sh", dispatcher)


if __name__ == "__main__":
    unittest.main()
