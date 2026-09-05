#!/usr/bin/env python3
"""Contracts for the installed owned-syslog family witness."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat" / "x86_64" / "run_owned_syslog.sh"
DOCUMENT = ROOT / "compat" / "x86_64" / "owned-syslog.md"


class OwnedSyslogTests(unittest.TestCase):
    def assert_replay_parser_usage(self, *arguments: str) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-syslog-parser.", dir=scratch
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

    def test_replay_parser_rejects_ambiguous_product_paths(self) -> None:
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

    def test_one_installed_driver_object_binds_every_link_receipt(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        document = DOCUMENT.read_text(encoding="utf-8")
        link_product = runner.split("link_product() {", 1)[1].split("\n}\n", 1)[0]

        self.assertIn('"$installed/bin/crabc-cc-dynamic" --dynamic-pie', runner)
        self.assertIn('"$work/workload.o"', runner)
        self.assertIn('"$oracle_cc" -static', runner)
        self.assertNotIn('-c "$probe"', link_product)
        self.assertIn("-ffreestanding -fno-builtin -fno-stack-protector -fPIE -E -H", runner)
        self.assertIn("R_X86_64_(32|32S)", runner)
        self.assertIn("owned_posix_product_evidence", runner)
        self.assertIn("validate_link", runner)
        self.assertIn("workload-object-binding.json", runner)
        self.assertIn("oracle-kernel-$scenario.status", runner)
        self.assertIn("provided static/static-PIE plus provided dynamic", runner)
        self.assertIn("single installed-header workload object", document)

    def test_replay_products_must_stay_below_the_checkout_work_boundary(self) -> None:
        scratch = ROOT / ".work" / "x86_64" / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        for label, arguments, expected in (
            (
                "static",
                ("--static-sysroot", str(ROOT)),
                "owned syslog static product must be a checkout .work directory",
            ),
            (
                "dynamic",
                (str(ROOT),),
                "owned syslog product must be a checkout .work directory",
            ),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory(dir=scratch) as temporary:
                result = subprocess.run(
                    ["bash", str(RUNNER), *arguments],
                    cwd=ROOT,
                    env={**os.environ, "TMPDIR": temporary},
                    capture_output=True,
                    text=True,
                    check=False,
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)
            self.assertNotIn("evidence:", result.stdout)


if __name__ == "__main__":
    unittest.main()
