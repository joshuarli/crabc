#!/usr/bin/env python3
"""Regression coverage for Git ownership across the Docker source mount."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DISPATCHER = ROOT / "scripts" / "dev.sh"


class DevContainerTests(unittest.TestCase):
    def test_sysroot_distribution_marks_the_source_mount_as_git_safe(self) -> None:
        """A container UID must be able to query the runner-owned checkout."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
            rustix = root / "rustix"
            rustix.mkdir()
            rustybench = root / "rustybench"
            rustybench.mkdir()
            capture = root / "docker.args"
            docker = bin_directory / "docker"
            docker.write_text(
                """#!/usr/bin/env bash
set -euo pipefail

case "$1" in
    image)
        if [[ "$2" == "inspect" ]]; then
            if [[ "${3:-}" == "--format" ]]; then
                printf 'arm64\\n'
            fi
            exit 0
        fi
        ;;
    run)
        printf '%s\\0' "$@" > "${FAKE_DOCKER_ARGS:?}"
        exit 0
        ;;
esac

printf 'unexpected docker invocation: %s\\n' "$*" >&2
exit 64
""",
                encoding="utf-8",
            )
            docker.chmod(docker.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.update(
                {
                    "CRABC_DEV_IMAGE": "crabc-test:aarch64",
                    "CRABC_TARGET_VOLUME": "crabc-test-target",
                    "CRABC_CARGO_VOLUME": "crabc-test-cargo",
                    "CRABC_RUSTIX_SOURCE_HOST": str(rustix),
                    "CRABC_RUSTYBENCH_SOURCE_HOST": str(rustybench),
                    "FAKE_DOCKER_ARGS": str(capture),
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                }
            )
            completed = subprocess.run(
                ["bash", str(DISPATCHER), "sysroot-dist"],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8"))

            arguments = [
                argument.decode("utf-8")
                for argument in capture.read_bytes().split(bytes((0,)))
                if argument
            ]
            argument_pairs = set(zip(arguments, arguments[1:]))
            self.assertTrue(
                {
                    ("--env", "GIT_CONFIG_COUNT=1"),
                    ("--env", "GIT_CONFIG_KEY_0=safe.directory"),
                    ("--env", "GIT_CONFIG_VALUE_0=/workspace"),
                }.issubset(argument_pairs),
                arguments,
            )


if __name__ == "__main__":
    unittest.main()
