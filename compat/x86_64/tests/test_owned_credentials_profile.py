#!/usr/bin/env python3
"""Regression boundaries for the installed credential-setter profile."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
PROBE = ROOT / "compat/x86_64/owned_credentials_profile_probe.c"
RUNNER = ROOT / "compat/x86_64/run_owned_credentials_profile.sh"


class OwnedCredentialsProfileTests(unittest.TestCase):
    def run_namespace_capture_harness(self, child_status: int) -> tuple[int, str, str, str]:
        source = RUNNER.read_text(encoding="utf-8")
        start = source.index("run_in_user_namespace_root() {")
        end = source.index("\nvalidate_transcript() {", start)
        runner = source[start:end]

        temporary_root = ROOT / ".work" / "x86_64" / "tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-credentials-profile-status.", dir=temporary_root
        ) as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            timeout = tools / "timeout"
            timeout.write_text("#!/bin/sh\nshift\nexec \"$@\"\n", encoding="utf-8")
            timeout.chmod(0o755)
            unshare = tools / "unshare"
            unshare.write_text(f"#!/bin/sh\nexit {child_status}\n", encoding="utf-8")
            unshare.chmod(0o755)
            harness = root / "harness.sh"
            output = root / "stdout"
            error = root / "stderr"
            harness.write_text(
                "#!/usr/bin/env bash\n"
                "set -u\n"
                f"{runner}\n"
                f"if run_in_user_namespace_root /root {output} {error} /consumer direct; then\n"
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

    def assert_parser_usage(self, *arguments: str) -> None:
        temporary_root = ROOT / ".work" / "x86_64" / "tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="owned-credentials-profile-parser.", dir=temporary_root
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

    def test_direct_setters_use_valid_current_ids_and_retain_raw_transcripts(self) -> None:
        source = PROBE.read_text(encoding="utf-8")

        self.assertIn("gid_t groups[1] = { before->effective_gid };", source)
        self.assertIn("result->status = setgroups(1, groups);", source)
        self.assertNotIn("setgroups((size_t)-1, NULL)", source)
        self.assertIn("result->status == -1 && result->error == EPERM", source)
        for name, call in (
            ("setresuid-current", "setresuid(before->real_uid, before->effective_uid,"),
            ("setresgid-current", "setresgid(before->real_gid, before->effective_gid,"),
            ("setuid-current", "setuid(before->effective_uid)"),
            ("setgid-current", "setgid(before->effective_gid)"),
        ):
            self.assertIn(name, source)
            self.assertIn(call, source)
        self.assertIn("status=%d errno=%d", source)
        self.assertIn("before=uid=%lu/%lu/%lu,gid=%lu/%lu/%lu", source)
        self.assertIn("after=uid=%lu/%lu/%lu,gid=%lu/%lu/%lu", source)
        self.assertIn("ids=unchanged", source)
        self.assertIn("fflush(stdout)", source)

    def test_runner_validates_raw_transcripts_and_every_linked_product(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")

        self.assertIn("validate_transcript", source)
        self.assertIn("aliases-profile", source)
        self.assertIn("--link-receipt", source)
        self.assertIn("owned_posix_product_evidence", source)
        self.assertIn("validate_link", source)
        for required in (
            "provided_static=''",
            "provided_dynamic=''",
            "static_was_supplied=0",
            "dynamic_was_supplied=0",
            "--static-sysroot)",
            "[ \"$static_was_supplied\" -eq 0 ] || usage",
            "[ \"$dynamic_was_supplied\" -eq 0 ] || usage",
            "case \"$2\" in -*) usage ;; esac",
            "credentials profile {name} product must be a checkout .work directory",
            "elif [ \"$dynamic_was_supplied\" -eq 0 ]; then",
            'static_product="$provided_static"',
        ):
            self.assertIn(required, source)

    def test_static_replay_parser_rejects_ambiguous_supplied_products(self) -> None:
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

    def test_namespace_runner_retains_actual_process_status(self) -> None:
        for child_status, expected_return in ((0, 0), (7, 1)):
            with self.subTest(child_status=child_status):
                returncode, output, status, error = self.run_namespace_capture_harness(child_status)
                self.assertEqual(returncode, 0)
                self.assertEqual(output, f"return={expected_return}\n")
                self.assertEqual(status, f"{child_status}\n")
                self.assertEqual(error, "")


if __name__ == "__main__":
    unittest.main()
