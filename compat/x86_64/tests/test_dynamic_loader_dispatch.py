#!/usr/bin/env python3
"""Observe the installed loader gate's Docker authority at dispatch time."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class DynamicLoaderDispatchTests(unittest.TestCase):
    def test_proc_mount_authority_is_confined_to_the_dynamic_product_gate(self):
        scratch = ROOT / ".work/x86_64/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
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
                "    raise SystemExit('unexpected Docker operation')\n"
            )
            docker.chmod(0o755)
            for command, needs_mount in (
                ("materialized-dynamic-sysroot", True),
                ("owned-dynamic-sysroot", True),
                ("libc-owned-wordexp", False),
                ("crt-object-bundle", False),
                ("qualification-manifest", False),
                ("qualification-manifest-prefix", False),
                ("owned-dynamic-io-cancellation", False),
                ("owned-system-cancellation", False),
                ("owned-dynamic-spawn", False),
                ("owned-atfork-registry", False),
                ("owned-signal-helpers", False),
                ("owned-signal-helpers-product", False),
                ("owned-linux-control", False),
                ("owned-assert", False),
                ("owned-syslog", False),
                ("owned-pthread-spin", False),
                ("owned-process-trio", False),
            ):
                with self.subTest(command=command):
                    capture = work / f"{command}.jsonl"
                    environment = dict(os.environ)
                    environment.update(
                        PATH=f"{work}{os.pathsep}{os.environ['PATH']}",
                        DISPATCH_CAPTURE=str(capture),
                        CRABC_X86_64_WORK_DIR=str(work / "state"),
                    )
                    selected_command = (["qualification-manifest", "--through", "compat.abi-differential"]
                        if command == "qualification-manifest-prefix" else
                        ["owned-signal-helpers", "/workspace/.work/x86_64/supplied-product"]
                        if command == "owned-signal-helpers-product" else [command])
                    result = subprocess.run(
                        ["bash", str(ROOT / "scripts/dev-x86_64.sh"), *selected_command],
                        cwd=ROOT, env=environment, capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    invocations = [json.loads(line) for line in capture.read_text().splitlines()]
                    self.assertTrue(invocations)
                    for arguments in invocations:
                        self.assertEqual("--cap-add=SYS_ADMIN" in arguments, needs_mount)
                        self.assertEqual("--security-opt=apparmor=unconfined" in arguments, needs_mount)
                        self.assertNotIn("--privileged", arguments)
                        self.assertNotIn("--pid=host", arguments)
                        self.assertNotIn("--userns=host", arguments)
                        self.assertIn("TMPDIR=/workspace/.work/x86_64/tmp", arguments)
                    if command in ("owned-dynamic-io-cancellation", "owned-system-cancellation", "owned-dynamic-spawn", "owned-linux-control", "owned-assert", "owned-atfork-registry", "owned-syslog", "owned-pthread-spin", "owned-process-trio", "owned-signal-helpers"):
                        self.assertEqual(len(invocations), 1)
                        self.assertIn("--cap-add=SYS_CHROOT", invocations[0])
                        self.assertEqual(invocations[0][-2:], [
                            "bash", "/workspace/compat/x86_64/run_" + command.replace("-", "_") + ".sh",
                        ])
                    if command == "owned-signal-helpers-product":
                        self.assertEqual(len(invocations), 1)
                        self.assertIn("--cap-add=SYS_CHROOT", invocations[0])
                        self.assertEqual(invocations[0][-3:], [
                            "bash", "/workspace/compat/x86_64/run_owned_signal_helpers.sh",
                            "/workspace/.work/x86_64/supplied-product",
                        ])
                    if command == "qualification-manifest":
                        self.assertEqual(len(invocations), 1)
                        self.assertEqual(invocations[0][-2:], [
                            "python3", "/workspace/compat/x86_64/run_qualification_manifest.py",
                        ])
                        self.assertIn("CRABC_WORK_DIR=/workspace/.work/x86_64", invocations[0])
                    if command == "qualification-manifest-prefix":
                        self.assertEqual(len(invocations), 1)
                        self.assertEqual(invocations[0][-4:], [
                            "python3", "/workspace/compat/x86_64/run_qualification_manifest.py",
                            "--through", "compat.abi-differential",
                        ])
                    if needs_mount:
                        self.assertEqual(len(invocations), 1)
                        self.assertIn("--cap-add=SYS_CHROOT", invocations[0])
                        self.assertEqual(invocations[0][-2:], [
                            "bash", ("/workspace/compat/x86_64/run_owned_dynamic_sysroot.sh"
                                     if command == "owned-dynamic-sysroot" else
                                     "/workspace/compat/x86_64/run_materialized_dynamic_sysroot.sh"),
                        ])


if __name__ == "__main__":
    unittest.main()
