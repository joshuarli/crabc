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
    def test_mount_authority_is_confined_to_dynamic_product_and_pty_gates(self):
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
                ("owned-pty", True),
                ("owned-pty-product", True),
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
                ("owned-named-ipc", False),
                ("owned-named-ipc-product", False),
                ("owned-message-queues", False),
                ("owned-message-queues-product", False),
                ("owned-linux-control", False),
                ("owned-kernel-residual", False),
                ("owned-vm-mechanisms", False),
                ("owned-group", False),
                ("owned-assert", False),
                ("owned-quick-exit", False),
                ("owned-legacy-time", False),
                ("owned-environment-lifecycle", False),
                ("owned-syslog", False),
                ("owned-credentials-profile", False),
                ("owned-credentials-profile-product", False),
                ("owned-pthread-spin", False),
                ("owned-process-trio", False),
                ("owned-process-control", False),
                ("owned-filesystem-mechanisms", True),
                ("owned-error-reporting", False),
                ("owned-passwd", False),
                ("owned-posix-filesystem", False),
                ("owned-unix-mechanisms", False),
                ("owned-passwd-product", False),
                ("owned-pattern", False),
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
                        [command.removesuffix("-product"), "/workspace/.work/x86_64/supplied-product"]
                        if command in ("owned-signal-helpers-product", "owned-pty-product", "owned-named-ipc-product", "owned-passwd-product", "owned-message-queues-product", "owned-credentials-profile-product") else [command])
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
                        self.assertEqual(
                            "--security-opt=seccomp=unconfined" in arguments,
                            command in (
                                "owned-credentials-profile",
                                "owned-credentials-profile-product",
                            ),
                        )
                        self.assertNotIn("--privileged", arguments)
                        self.assertNotIn("--pid=host", arguments)
                        self.assertNotIn("--ipc=host", arguments)
                        self.assertNotIn("--userns=host", arguments)
                        self.assertIn("TMPDIR=/workspace/.work/x86_64/tmp", arguments)
                    if command in ("owned-dynamic-io-cancellation", "owned-system-cancellation", "owned-dynamic-spawn", "owned-linux-control", "owned-kernel-residual", "owned-assert", "owned-quick-exit", "owned-legacy-time", "owned-environment-lifecycle", "owned-atfork-registry", "owned-syslog", "owned-credentials-profile", "owned-pthread-spin", "owned-process-trio", "owned-process-control", "owned-signal-helpers", "owned-filesystem-mechanisms", "owned-error-reporting", "owned-named-ipc", "owned-vm-mechanisms", "owned-passwd", "owned-group", "owned-message-queues", "owned-pattern", "owned-posix-filesystem", "owned-unix-mechanisms"):
                        self.assertEqual(len(invocations), 1)
                        self.assertIn("--cap-add=SYS_CHROOT", invocations[0])
                        self.assertEqual(invocations[0][-2:], [
                            "bash", "/workspace/compat/x86_64/run_" + command.replace("-", "_") + ".sh",
                        ])
                    if command in ("owned-signal-helpers-product", "owned-pty-product", "owned-passwd-product", "owned-credentials-profile-product"):
                        self.assertEqual(len(invocations), 1)
                        self.assertIn("--cap-add=SYS_CHROOT", invocations[0])
                        self.assertEqual(invocations[0][-3:], [
                            "bash", "/workspace/compat/x86_64/run_" + command.removesuffix("-product").replace("-", "_") + ".sh",
                            "/workspace/.work/x86_64/supplied-product",
                        ])
                    if command == "owned-named-ipc-product":
                        self.assertEqual(len(invocations), 1)
                        self.assertIn("--cap-add=SYS_CHROOT", invocations[0])
                        self.assertEqual(invocations[0][-3:], [
                            "bash", "/workspace/compat/x86_64/run_owned_named_ipc.sh",
                            "/workspace/.work/x86_64/supplied-product",
                        ])
                    if command == "owned-message-queues-product":
                        self.assertEqual(len(invocations), 1)
                        self.assertIn("--cap-add=SYS_CHROOT", invocations[0])
                        self.assertEqual(invocations[0][-3:], [
                            "bash", "/workspace/compat/x86_64/run_owned_message_queues.sh",
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
                    if command == "owned-pty":
                        self.assertEqual(len(invocations), 1)
                        self.assertIn("--cap-add=SYS_CHROOT", invocations[0])
                        self.assertEqual(invocations[0][-2:], [
                            "bash", "/workspace/compat/x86_64/run_owned_pty.sh",
                        ])
                    if needs_mount and command not in ("owned-pty", "owned-pty-product"):
                        self.assertEqual(len(invocations), 1)
                        self.assertIn("--cap-add=SYS_CHROOT", invocations[0])
                        expected_runner = {
                            "materialized-dynamic-sysroot": "/workspace/compat/x86_64/run_materialized_dynamic_sysroot.sh",
                            "owned-dynamic-sysroot": "/workspace/compat/x86_64/run_owned_dynamic_sysroot.sh",
                            "owned-filesystem-mechanisms": "/workspace/compat/x86_64/run_owned_filesystem_mechanisms.sh",
                        }[command]
                        self.assertEqual(invocations[0][-2:], ["bash", expected_runner])


if __name__ == "__main__":
    unittest.main()
