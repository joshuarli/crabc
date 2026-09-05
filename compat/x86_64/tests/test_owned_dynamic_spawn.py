"""Supplied static spawn replay preserves one object and complete raw results."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/x86_64/run_owned_dynamic_spawn.sh"
DOCUMENT = ROOT / "compat/x86_64/dynamic-product-qualification.md"


class OwnedDynamicSpawnTests(unittest.TestCase):
    def scratch(self):
        path = ROOT / ".work/x86_64/tmp"
        path.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=path)
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def function(self, name):
        match = re.search(r"^" + name + r"\(\) \{\n.*?^\}", RUNNER.read_text(), re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match, f"missing isolated {name} boundary")
        return match.group(0)

    def test_invalid_replay_arguments_fail_before_output_or_build(self):
        scratch = self.scratch()
        for arguments in (
            ["--static-sysroot"], ["--static-sysroot", ""], [""],
            ["--static-sysroot", "--unknown"], ["--static-sysroot", "-x"],
            ["--unknown"], ["-x"], [str(ROOT), str(ROOT)], [str(ROOT), ""],
            ["--static-sysroot", str(ROOT), "--static-sysroot", str(ROOT)],
            ["--static-sysroot", str(ROOT), ""],
        ):
            with self.subTest(arguments=arguments):
                result = subprocess.run(["bash", str(RUNNER), *arguments], cwd=ROOT,
                    env={**os.environ, "TMPDIR": str(scratch)}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr,
                    f"usage: {RUNNER} [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]\n")
                self.assertEqual(list(scratch.iterdir()), [])

    def test_ambient_static_or_dynamic_product_fails_before_evidence(self):
        scratch = self.scratch()
        for arguments in ([str(ROOT)], ["--static-sysroot", str(ROOT)]):
            result = subprocess.run(["bash", str(RUNNER), *arguments], cwd=ROOT,
                env={**os.environ, "TMPDIR": str(scratch)}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(list(scratch.iterdir()), [])

    def test_capture_preserves_exit_status_and_raw_streams(self):
        function = self.function("run_in_root")
        work = self.scratch()
        for status in (0, 7, 124):
            with self.subTest(status=status):
                child = work / f"chroot-{status}"
                child.write_text(f"#!/bin/sh\nprintf 'raw out\\n'\nprintf 'raw err\\n' >&2\nexit {status}\n")
                child.chmod(0o755)
                output = work / f"result-{status}.stdout"
                result = subprocess.run(["bash", "-c", "set -euo pipefail\nCHROOT=$1\n" + function
                    + '\nrun_in_root "$2" "$3" /consumer /spawn-state\n', "spawn-capture",
                    str(child), str(work), str(output)], capture_output=True, text=True)
                self.assertEqual(result.returncode, status)
                self.assertEqual(output.read_text(), "raw out\n")
                self.assertEqual(output.with_suffix(".stderr").read_text(), "raw err\n")
                self.assertEqual(output.with_suffix(".status").read_text(), f"{status}\n")

    def test_comparison_rejects_each_raw_result_difference(self):
        function = self.function("compare_oracle")
        work = self.scratch()
        for suffix, value in (("stdout", "owned-spawn-ok\n"), ("stderr", ""), ("status", "0\n")):
            (work / f"oracle.{suffix}").write_text(value)
            (work / f"candidate.{suffix}").write_text(value)
        command = ["bash", "-c", "set -euo pipefail\nwork=$1\n" + function
                   + '\ncompare_oracle candidate\n', "spawn-compare", str(work)]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        for suffix in ("stdout", "stderr", "status"):
            path = work / f"candidate.{suffix}"
            original = path.read_text()
            path.write_text("changed\n")
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            path.write_text(original)

    def test_static_is_opt_in_and_all_links_use_the_one_object_and_shared_validator(self):
        runner = RUNNER.read_text()
        self.assertNotIn("build_x86_64_owned_sysroot.py", runner)
        self.assertEqual(runner.count("subprocess.run(actual_command,"), 1)
        self.assertIn('-DCRABC_SPAWN_EXECUTABLE="/consumer"', runner)
        for required in (
            'if [ -n "$provided_static" ]; then',
            '"$provided_static/bin/crabc-cc" "-$mode"',
            "--link-receipt", "from owned_posix_product_evidence import validate_link",
            'validate_sealed_link "$provided_static"', 'validate_sealed_link "$installed"',
            "link-identity.json", 'for mode in static static-pie',
            'for mode in pie non-pie', 'for entry in kernel direct',
        ):
            self.assertIn(required, runner)

    def test_compile_receipt_binds_the_installed_driver_headers_and_immutable_object(self):
        runner = RUNNER.read_text()
        document = DOCUMENT.read_text()

        for required in (
            "compile.json", "workload.d", "actual_command", "dependency_audit_command",
            "installed_driver", "installed_helper", "compiler", "clean_environment",
            "import crabc_cc_static as compiler_contract", "compiler_contract.compiler()",
            "compiler_contract.clean_environment()", "CRABC_SPAWN_EXECUTABLE",
            "'-nostdinc'", "'-isystem'", "'-ffreestanding'",
            "'-fstack-protector-strong'", "'-fPIE'", "required_headers",
            "spawn.h", "sys/resource.h", "pthread.h", "object_sha256",
            "assert_compile_receipt", "workload changed after compilation",
            "installed header changed after compilation",
        ):
            self.assertIn(required, runner)
        self.assertNotIn('"/usr/bin/gcc"', runner)
        self.assertLess(
            runner.index("actual_command = [str(driver), '--dynamic-pie'"),
            runner.index('"$oracle_cc" -static'),
        )
        self.assertLess(
            runner.rindex("dependency_audit_command = [str(compiler),"),
            runner.index('"$oracle_cc" -static'),
        )
        self.assertLess(
            runner.index("assert_compile_receipt\n\"$oracle_cc\""),
            runner.index('"$oracle_cc" -static'),
        )
        self.assertGreaterEqual(runner.count("assert_compile_receipt"), 7)
        for required in (
            "`compile.json`", "installed shared compiler helper", "exact `/consumer` compile command",
            "records every installed header", "before and after every oracle, static, and",
        ):
            self.assertIn(required, document)


if __name__ == "__main__":
    unittest.main()
