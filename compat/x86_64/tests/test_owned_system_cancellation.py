#!/usr/bin/env python3
"""The owned system-cancellation replay interface stays unambiguous."""

from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_system_cancellation.sh"
DOCUMENT = ROOT / "compat/x86_64/owned-system-cancellation.md"


class OwnedSystemCancellationTests(unittest.TestCase):
    def test_static_replay_parser_rejects_incomplete_or_ambiguous_arguments(
        self,
    ) -> None:
        invalid_arguments = (
            ("--static-sysroot",),
            ("--static-sysroot", ""),
            ("--static-sysroot", "--not-a-product"),
            ("--static-sysroot", "first", "--static-sysroot", "second"),
            ("first-dynamic", "second-dynamic"),
        )

        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    ["bash", str(RUNNER), *arguments],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr,
                    "usage: "
                    f"{RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n",
                )

    def test_two_role_replay_keeps_installed_headers_and_sealed_raw_evidence(
        self,
    ) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        document = " ".join(DOCUMENT.read_text(encoding="utf-8").split())

        for required in (
            "provided_static=''",
            "provided_dynamic=''",
            "dynamic_was_supplied=0",
            "realpath -e --",
            "system cancellation {name} product must be a checkout .work directory",
            '"$installed_dynamic/bin/crabc-cc-dynamic" --dynamic-pie',
            '-fno-stack-protector -c "$PROBE" -o "$work/consumer.o"',
            '-fno-stack-protector -c "$CHILD" -o "$work/child.o"',
            "audit_canonical_objects",
            "audit_musl_links",
            "crabc.system-cancellation-compile/v1",
            '"effective_codegen_flag": "-fPIE"',
            '"not_selected": ["-fPIC", "-fno-pie"]',
            "consumer and child objects unexpectedly coincide",
            "--link-receipt",
            "crabc.system-cancellation-link/v1",
            "for suffix in stdout stderr status",
            "local -a modes=(static static-pie)",
            "modes=(pie non-pie)",
            "run_direct_consumer",
            "dynamic trace omitted a direct owned or canonical object input",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("from owned_posix_product_evidence", runner)
        self.assertNotIn("import owned_posix_product_evidence", runner)
        self.assertNotIn("validate_link(", runner)
        self.assertLess(
            runner.index('"$installed_dynamic/bin/crabc-cc-dynamic" --dynamic-pie'),
            runner.index('TMPDIR="$work" "$ORACLE_CC"'),
        )
        self.assertLess(
            runner.index('audit_canonical_objects "$installed_dynamic"'),
            runner.index("\naudit_musl_links\n"),
        )
        for required in (
            "two distinct installed-header objects",
            "consumer",
            "child",
            "-fPIE",
            "-fPIC",
            "pinned musl",
            "static/static-PIE",
            "dynamic PIE/non-PIE",
            "kernel and direct interpreter",
            "--static-sysroot STATIC_SYSROOT",
            "neither producer",
            "stdout, stderr, and status",
            "system(3)",
            "pclose(3)",
            "supervisor",
        ):
            self.assertIn(required, document)


if __name__ == "__main__":
    unittest.main()
