#!/usr/bin/env python3
"""Regression boundaries for the owned Linux-control product replay."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_linux_control.sh"


class OwnedLinuxControlRunnerTests(unittest.TestCase):
    def assert_parser_usage(self, *arguments: str) -> None:
        temporary_root = ROOT / ".work" / "x86_64" / "tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-linux-control-parser.", dir=temporary_root
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

    def run_capture_harness(self, child_status: int) -> tuple[int, str, str, str]:
        source = RUNNER.read_text(encoding="utf-8")
        start = source.index("run_capture() {")
        end = source.index("\ncompare_oracle() {", start)
        runner = source[start:end]

        temporary_root = ROOT / ".work" / "x86_64" / "tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-linux-control-status.", dir=temporary_root
        ) as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            timeout = tools / "timeout"
            timeout.write_text("#!/bin/sh\nshift\nexec \"$@\"\n", encoding="utf-8")
            timeout.chmod(0o755)
            chroot = tools / "chroot"
            chroot.write_text(f"#!/bin/sh\nexit {child_status}\n", encoding="utf-8")
            chroot.chmod(0o755)
            harness = root / "harness.sh"
            output = root / "stdout"
            error = Path(str(output) + ".stderr")
            harness.write_text(
                "#!/usr/bin/env bash\n"
                "set -u\n"
                f"{runner}\n"
                f"if run_capture {output} chroot /root /consumer; then\n"
                "    printf 'return=0\\n'\n"
                "else\n"
                "    printf 'return=%s\\n' \"$?\"\n"
                "fi\n",
                encoding="utf-8",
            )
            harness.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = f"{tools}{os.pathsep}{environment['PATH']}"
            result = subprocess.run(
                ["bash", str(harness)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            return (
                result.returncode,
                result.stdout,
                output.with_suffix(".status").read_text(encoding="utf-8"),
                error.read_text(encoding="utf-8"),
            )

    def test_parser_rejects_ambiguous_supplied_products(self) -> None:
        for label, arguments in (
            ("missing static", ("--static-sysroot",)),
            ("empty static", ("--static-sysroot", "")),
            ("empty dynamic", ("",)),
            ("option static", ("--static-sysroot", "--not-a-sysroot")),
            ("duplicate static", ("--static-sysroot", "/one", "--static-sysroot", "/two")),
            ("duplicate dynamic", ("/one", "/two")),
        ):
            with self.subTest(label=label):
                self.assert_parser_usage(*arguments)

    def test_capture_retains_actual_process_status(self) -> None:
        for child_status, expected_return in ((0, 0), (7, 1)):
            with self.subTest(child_status=child_status):
                returncode, output, status, error = self.run_capture_harness(child_status)
                self.assertEqual(returncode, 0)
                self.assertEqual(output, f"return={expected_return}\n")
                self.assertEqual(status, f"{child_status}\n")
                self.assertEqual(error, "")

    def test_runner_retains_shared_link_identities_and_raw_triplets(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")

        for required in (
            "provided_static=''",
            "static_was_supplied=0",
            "dynamic_was_supplied=0",
            "--link-receipt",
            "from owned_posix_product_evidence import validate_link",
            "link-identities.json",
            "compile.json",
            'cmp "$work/oracle.stdout.stderr"',
            'cmp "$work/oracle.stdout.status"',
            'static_product="$provided_static"',
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
