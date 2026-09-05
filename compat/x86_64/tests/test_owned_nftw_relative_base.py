#!/usr/bin/env python3
"""Contract wiring for the installed relative nftw metadata regression."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
PROBE = ROOT / "compat/x86_64/owned_nftw_relative_base_probe.c"
RUNNER = ROOT / "compat/x86_64/run_owned_nftw_relative_base.sh"
DOCUMENT = ROOT / "compat/x86_64/owned-nftw-relative-base.md"
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"
TRAVERSAL = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "filesystem_traversal.rs"


class OwnedNftwRelativeBaseTests(unittest.TestCase):
    def test_probe_retains_the_relative_os_test_callback_contract(self) -> None:
        source = PROBE.read_text(encoding="utf-8")
        for required in (
            'nftw(".", visit, 1024, FTW_DEPTH)',
            '"./ftw/nftw"',
            '"./ftw"',
            'info->base != 6',
            'info->base != 2',
            'info->base != 0',
            'info->level != 2',
            'info->level != 1',
            'info->level != 0',
            'strcmp(path + info->base, "nftw")',
            'strcmp(path + info->base, "ftw")',
        ):
            self.assertIn(required, source)
        self.assertIn('chdir("/work")', source)

    def test_runner_binds_one_installed_object_to_musl_and_owned_entries(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for required in (
            'validate-dynamic-product',
            'audit-dynamic',
            'crabc-cc-dynamic" --dynamic-pie',
            '"$work/workload.o"',
            '"$ORACLE_CC" -static',
            'pie non-pie',
            'kernel direct',
            'prepare_root',
            'work/ftw/nftw',
            'cmp "$work/oracle.stdout"',
            'cmp "$work/oracle.stderr"',
            'cmp "$work/oracle.status"',
        ):
            self.assertIn(required, source)
        self.assertIn('owned-nftw-relative-base)', DISPATCHER.read_text(encoding="utf-8"))

    def test_dispatch_accepts_and_translates_only_an_optional_dynamic_product(self) -> None:
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            state = work / "state"
            product = state / "dynamic product"
            product.mkdir(parents=True)
            capture = work / "docker.jsonl"
            docker = work / "docker"
            docker.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "if sys.argv[1:3] == ['image', 'inspect']:\n"
                "    print('linux/amd64')\n"
                "elif sys.argv[1] == 'run':\n"
                "    with open(os.environ['DISPATCH_CAPTURE'], 'a') as output:\n"
                "        output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "else:\n"
                "    raise SystemExit('unexpected Docker operation')\n",
                encoding="utf-8",
            )
            docker.chmod(0o755)
            environment = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("CRABC_X86_64_")
            }
            environment.update(
                PATH=f"{work}{os.pathsep}{os.environ['PATH']}",
                DISPATCH_CAPTURE=str(capture),
                CRABC_X86_64_WORK_DIR=str(state),
            )

            for arguments, expected in (
                ([], []),
                ([str(product)], ["/workspace/.work/x86_64/dynamic product"]),
            ):
                with self.subTest(arguments=arguments):
                    capture.unlink(missing_ok=True)
                    result = subprocess.run(
                        ["bash", str(DISPATCHER), "owned-nftw-relative-base", *arguments],
                        cwd=ROOT,
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    invocations = [
                        json.loads(line) for line in capture.read_text(encoding="utf-8").splitlines()
                    ]
                    self.assertEqual(len(invocations), 1)
                    self.assertIn("--cap-add=SYS_CHROOT", invocations[0])
                    self.assertNotIn("--privileged", invocations[0])
                    self.assertEqual(
                        invocations[0][-(2 + len(expected)):],
                        [
                            "bash",
                            "/workspace/compat/x86_64/run_owned_nftw_relative_base.sh",
                            *expected,
                        ],
                    )

            capture.unlink(missing_ok=True)
            malformed = subprocess.run(
                ["bash", str(DISPATCHER), "owned-nftw-relative-base", "--static-sysroot"],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(malformed.returncode, 2, malformed.stderr)
            self.assertIn("usage:", malformed.stderr)
            self.assertFalse(capture.exists())

    def test_walk_carries_the_next_child_base_separately_from_callback_base(self) -> None:
        source = TRAVERSAL.read_text(encoding="utf-8")
        for required in (
            'child_base: c_int',
            'let callback_base = if history.is_null()',
            '(*history).child_base',
            'let child_base = (last + 1) as c_int;',
            'child_base,',
        ):
            self.assertIn(required, source)

    def test_document_names_the_history_base_boundary(self) -> None:
        source = DOCUMENT.read_text(encoding="utf-8")
        for required in (
            'src/misc/nftw.c',
            '`lev.base`',
            '`new.base`',
            '`filesystem_traversal.rs`',
            'kernel interpreter',
            'direct `/lib/ld-crabc-x86_64.so.1`',
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
