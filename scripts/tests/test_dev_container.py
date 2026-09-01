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
    def test_dispatcher_binds_repository_work_directories_by_default(self) -> None:
        """Default caches stay below the checkout instead of in named volumes."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
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
            environment.pop("CRABC_WORK_DIR", None)
            environment.pop("CRABC_TARGET_VOLUME", None)
            environment.pop("CRABC_CARGO_VOLUME", None)
            environment.update(
                {
                    "CRABC_DEV_IMAGE": "crabc-test:aarch64",
                    "FAKE_DOCKER_ARGS": str(capture),
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                }
            )
            completed = subprocess.run(
                ["bash", str(DISPATCHER), "structure"],
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
            self.assertIn(("--env", "CARGO_HOME=/workspace/.work/cargo"), argument_pairs)
            self.assertIn(("--env", "PYTHONDONTWRITEBYTECODE=1"), argument_pairs)
            self.assertIn(("--env", "TMPDIR=/workspace/.work/tmp"), argument_pairs)
            self.assertIn(
                ("--volume", f"{ROOT / '.work'}:/workspace/.work"),
                argument_pairs,
            )
            self.assertIn(
                ("--volume", f"{ROOT / '.work' / 'target'}:/workspace/target"),
                argument_pairs,
            )
            self.assertIn(
                ("--volume", f"{ROOT / '.work' / 'cargo'}:/workspace/.work/cargo"),
                argument_pairs,
            )
            self.assertNotIn("crabc-target-aarch64:/workspace/target", arguments)
            self.assertNotIn("crabc-cargo-aarch64:/workspace/.work/cargo", arguments)

    def test_structure_runs_in_pinned_container(self) -> None:
        """The structure gate must not depend on the host Python version."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
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
                    "FAKE_DOCKER_ARGS": str(capture),
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                }
            )
            completed = subprocess.run(
                ["bash", str(DISPATCHER), "structure"],
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
            self.assertEqual(arguments[-2:], ["python3", "scripts/check_structure.py"])

    def test_dispatcher_runs_without_optional_oracle_mounts(self) -> None:
        """Optional oracle checkouts must not make the native dispatcher fail."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_directory = root / "bin"
            bin_directory.mkdir()
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
                    "CRABC_RUSTIX_SOURCE_HOST": str(root / "missing-rustix"),
                    "CRABC_RUSTYBENCH_SOURCE_HOST": str(root / "missing-rustybench"),
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
            self.assertNotIn("CRABC_RUSTIX_SOURCE=/opt/rustix", arguments)
            self.assertNotIn("CRABC_RUSTYBENCH_SOURCE=/opt/rustybench", arguments)

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
