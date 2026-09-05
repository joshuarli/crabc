#!/usr/bin/env python3
"""Contracts for the installed clone, vfork, and daemon evidence."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
DOCUMENT = ROOT / "compat" / "x86_64" / "owned-process-trio.md"
PRODUCT_EVIDENCE = ROOT / "compat" / "x86_64" / "owned_posix_product_evidence.py"
PROBE = ROOT / "compat" / "x86_64" / "owned_process_trio_probe.c"
RUNNER = ROOT / "compat" / "x86_64" / "run_owned_process_trio.sh"


class OwnedProcessTrioTests(unittest.TestCase):
    def assert_replay_parser_usage(self, *arguments: str) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-process-trio-parser.", dir=scratch
        ) as temporary:
            tools = Path(temporary) / "tools"
            tools.mkdir()
            python = tools / "python3"
            python.write_text("#!/bin/sh\nexit 79\n", encoding="utf-8")
            python.chmod(0o755)
            result = subprocess.run(
                ["bash", str(RUNNER), *arguments],
                cwd=ROOT,
                env={**os.environ, "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}"},
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

    def test_static_replay_parser_rejects_ambiguous_supplied_products(self) -> None:
        for label, arguments in (
            ("missing static", ("--static-sysroot",)),
            ("empty static", ("--static-sysroot", "")),
            ("empty dynamic", ("",)),
            ("option static", ("--static-sysroot", "--not-a-sysroot")),
            ("short option static", ("--static-sysroot", "-e")),
            ("option dynamic", ("--not-a-sysroot",)),
            ("short option dynamic", ("-e",)),
            ("duplicate static", ("--static-sysroot", "/one", "--static-sysroot", "/two")),
            ("duplicate dynamic", ("/one", "/two")),
        ):
            with self.subTest(label=label):
                self.assert_replay_parser_usage(*arguments)

    def test_static_and_dynamic_replay_paths_cannot_name_the_same_product(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-process-trio-duplicate-product.", dir=scratch
        ) as temporary:
            product = Path(temporary) / "product"
            product.mkdir()
            alias = Path(temporary) / "product-alias"
            alias.symlink_to(product, target_is_directory=True)

            self.assert_replay_parser_usage(
                "--static-sysroot", str(product), str(alias)
            )

    def test_one_installed_object_runs_the_full_sealed_product_matrix(self) -> None:
        document = DOCUMENT.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        for required in (
            "clone_cases",
            "vfork_cases",
            "daemon_cases",
            '"errors"',
            '"redirect"',
            "CLONE_VM | CLONE_VFORK",
            "pthread_atfork",
            "PR_SET_CHILD_SUBREAPER",
            "owned-process-trio-errors-ok",
            "owned-process-trio-redirect-ok",
        ):
            self.assertIn(required, probe)

        for required in (
            "provided_static=''",
            "provided_dynamic=''",
            "static_was_supplied=0",
            "dynamic_was_supplied=0",
            "--static-sysroot)",
            "for scenario in ordinary errors redirect",
            "crabc-cc-dynamic",
            "--dynamic-pie -std=c11 -fno-builtin",
            '"$work/workload.o"',
            "--link-receipt",
            "validate_sealed_link",
            "from owned_posix_product_evidence import validate_link",
            "link-identities.json",
            "static static-pie",
            "pie non-pie",
            "kernel",
            "direct",
            "oracle-$scenario.stderr",
            "oracle-$scenario.status",
            "provided static/static-PIE plus provided dynamic PIE/non-PIE",
        ):
            self.assertIn(required, runner)

        for required in (
            "`--static-sysroot`",
            "one installed-driver workload object",
            "static/static-PIE",
            "dynamic PIE/non-PIE",
            "status/stdout/stderr",
            "dynamic-only replay",
            "neither producer",
            "`owned_posix_product_evidence.validate_link`",
        ):
            self.assertIn(required, document)
        self.assertIn("def validate_link(", PRODUCT_EVIDENCE.read_text(encoding="utf-8"))

    def test_each_link_is_audited_before_its_raw_process_result_is_compared(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertLess(
            runner.index('validate_sealed_link "$static_product"'),
            runner.index('compare_oracle "static-$mode"'),
        )
        self.assertLess(
            runner.index('validate_sealed_link "$installed"'),
            runner.index('compare_oracle "dynamic-$mode-kernel"'),
        )
        for comparison in (
            'cmp "$work/oracle-$scenario.stdout" "$work/$label-$scenario.stdout"',
            'cmp "$work/oracle-$scenario.stderr" "$work/$label-$scenario.stderr"',
            'cmp "$work/oracle-$scenario.status" "$work/$label-$scenario.status"',
        ):
            self.assertIn(comparison, runner)

    def test_installed_driver_compile_provenance_rejects_foreign_headers(self) -> None:
        document = DOCUMENT.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")

        for required in (
            "compile.json",
            "workload.d",
            "import crabc_cc_static as compiler_contract",
            "compiler_contract.compiler()",
            "compiler_contract.clean_environment()",
            "'-nostdinc'",
            "'-isystem'",
            "headers = (product / 'usr/include').resolve(strict=True)",
            "'-ffreestanding'",
            "'-fstack-protector-strong'",
            "'-fPIE'",
            "dependency_audit_command",
            "driver_sha256",
            "manifest_sha256",
            "source_sha256",
            "object_sha256",
            "path != source_path and not path.is_relative_to(headers)",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("/usr/bin/gcc", runner)
        self.assertLess(
            runner.index('"$installed/bin/crabc-cc-dynamic" --dynamic-pie'),
            runner.index("dependency_command = [compiler_contract.compiler()"),
        )
        self.assertLess(
            runner.index("dependency_command = [compiler_contract.compiler()"),
            runner.index('"$oracle_cc" -static'),
        )
        self.assertIn("installed-header dependency audit", document)

    def test_retained_link_identities_match_the_selected_product_matrix(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")

        self.assertIn("'expected_linkages': sorted(expected_linkages)", runner)
        self.assertIn("retain_link_identities static static-pie pie non-pie", runner)
        self.assertIn("retain_link_identities pie non-pie", runner)
        self.assertLess(
            runner.index('if [ -n "$static_product" ]; then\n    retain_link_identities'),
            runner.index("matrix='provided static/static-PIE"),
        )

    def test_supplied_product_escape_is_rejected_before_building(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            for arguments, expected in (
                ((str(ROOT),), "dynamic"),
                (("--static-sysroot", str(ROOT)), "static"),
            ):
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        ["bash", str(RUNNER), *arguments],
                        cwd=ROOT,
                        env={**os.environ, "TMPDIR": temporary},
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        f"process-trio {expected} product must be a checkout .work directory",
                        result.stderr,
                    )
                    self.assertNotIn("evidence:", result.stdout)


if __name__ == "__main__":
    unittest.main()
