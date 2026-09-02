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
    @staticmethod
    def _work_temporary_directory() -> tempfile.TemporaryDirectory[str]:
        test_tmp = ROOT / ".work" / "tmp"
        test_tmp.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=test_tmp)

    @staticmethod
    def _write_fake_docker(root: Path) -> tuple[Path, Path]:
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
        return bin_directory, capture

    def test_dispatcher_rejects_named_docker_volume_overrides(self) -> None:
        """Mutable cache overrides must be host paths, never Docker volumes."""

        with self._work_temporary_directory() as temporary:
            root = Path(temporary)
            bin_directory, capture = self._write_fake_docker(root)
            for override in ("CRABC_TARGET_VOLUME", "CRABC_CARGO_VOLUME"):
                with self.subTest(override=override):
                    if capture.exists():
                        capture.unlink()
                    environment = os.environ.copy()
                    environment.pop("CRABC_WORK_DIR", None)
                    environment.pop("CRABC_TARGET_VOLUME", None)
                    environment.pop("CRABC_CARGO_VOLUME", None)
                    environment.update(
                        {
                            "CRABC_DEV_IMAGE": "crabc-test:aarch64",
                            override: "crabc-test-cache",
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

                    self.assertEqual(completed.returncode, 2, completed.stderr.decode("utf-8"))
                    self.assertIn(b"named Docker volumes", completed.stderr)
                    self.assertFalse(capture.exists())

    def test_dispatcher_accepts_checkout_work_descendant_bind_overrides(self) -> None:
        """An explicit worktree-local host path remains a supported override."""

        with self._work_temporary_directory() as temporary:
            root = Path(temporary)
            bin_directory, capture = self._write_fake_docker(root)
            work_dir = root / "selected-work"
            target_dir = work_dir / "target-cache"
            cargo_dir = work_dir / "cargo-cache"

            environment = os.environ.copy()
            environment.pop("CRABC_WORK_DIR", None)
            environment.pop("CRABC_TARGET_VOLUME", None)
            environment.pop("CRABC_CARGO_VOLUME", None)
            environment.update(
                {
                    "CRABC_DEV_IMAGE": "crabc-test:aarch64",
                    "CRABC_WORK_DIR": str(work_dir.relative_to(ROOT)),
                    "CRABC_TARGET_VOLUME": "./target-cache",
                    "CRABC_CARGO_VOLUME": "./cargo-cache",
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
            self.assertIn(("--volume", f"{work_dir}:/workspace/.work"), argument_pairs)
            self.assertIn(("--volume", f"{target_dir}:/workspace/target"), argument_pairs)
            self.assertIn(
                ("--volume", f"{cargo_dir}:/workspace/.work/cargo"),
                argument_pairs,
            )
            self.assertTrue((work_dir / "reports").is_dir())
            self.assertTrue((work_dir / "tmp").is_dir())
            self.assertTrue(target_dir.is_dir())
            self.assertTrue(cargo_dir.is_dir())

    def test_dispatcher_rejects_external_mutable_path_overrides(self) -> None:
        """Work-root, target, and Cargo paths cannot escape the checkout."""

        outside = ROOT.parent / "dispatcher-boundary-escape"
        cases = (
            ("CRABC_WORK_DIR", str(outside)),
            ("CRABC_TARGET_VOLUME", str(outside)),
            ("CRABC_CARGO_VOLUME", str(outside)),
        )
        for name, configured_path in cases:
            with self.subTest(name=name):
                environment = os.environ.copy()
                environment.pop("CRABC_WORK_DIR", None)
                environment.pop("CRABC_TARGET_VOLUME", None)
                environment.pop("CRABC_CARGO_VOLUME", None)
                environment[name] = configured_path
                completed = subprocess.run(
                    ["bash", str(DISPATCHER), "help"],
                    cwd=ROOT,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                self.assertEqual(completed.returncode, 2, completed.stderr.decode("utf-8"))
                self.assertIn(b"must resolve below", completed.stderr)

    def test_dispatcher_rejects_parent_path_components(self) -> None:
        """No mutable-path override may use parent-directory traversal."""

        cases = (
            ("CRABC_WORK_DIR", ".work/../dispatcher-boundary-escape"),
            ("CRABC_TARGET_VOLUME", "../target-cache"),
            ("CRABC_CARGO_VOLUME", "../cargo-cache"),
        )
        for name, configured_path in cases:
            with self.subTest(name=name):
                environment = os.environ.copy()
                environment.pop("CRABC_WORK_DIR", None)
                environment.pop("CRABC_TARGET_VOLUME", None)
                environment.pop("CRABC_CARGO_VOLUME", None)
                environment[name] = configured_path
                completed = subprocess.run(
                    ["bash", str(DISPATCHER), "help"],
                    cwd=ROOT,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                self.assertEqual(completed.returncode, 2, completed.stderr.decode("utf-8"))
                self.assertIn(b"must not contain '..'", completed.stderr)

    def test_dispatcher_rejects_symlink_escape(self) -> None:
        """A host path under .work cannot resolve through a symlink outside it."""

        with self._work_temporary_directory() as temporary:
            escape = Path(temporary) / "escape"
            escape.symlink_to(ROOT, target_is_directory=True)
            environment = os.environ.copy()
            environment.pop("CRABC_WORK_DIR", None)
            environment.pop("CRABC_TARGET_VOLUME", None)
            environment.pop("CRABC_CARGO_VOLUME", None)
            environment["CRABC_TARGET_VOLUME"] = str(escape)
            completed = subprocess.run(
                ["bash", str(DISPATCHER), "help"],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr.decode("utf-8"))
            self.assertIn(b"must resolve below", completed.stderr)

    def test_dispatcher_binds_repository_work_directories_by_default(self) -> None:
        """Default caches stay below the checkout instead of in named volumes."""

        with self._work_temporary_directory() as temporary:
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

    def test_allocator_quick_mounts_its_trusted_common_git_directory(self) -> None:
        """Allocator provenance must work when the checkout is a linked worktree."""

        with self._work_temporary_directory() as temporary:
            root = Path(temporary)
            bin_directory, capture = self._write_fake_docker(root)
            common_directory = root / "git-common"
            common_directory.mkdir()
            untrusted_directory = root / "untrusted-git-common"
            untrusted_directory.mkdir()
            git = bin_directory / "git"
            git.write_text(
                """#!/usr/bin/env bash
set -euo pipefail

if [[ "$*" == *"rev-parse --path-format=absolute --git-common-dir" ]]; then
    printf '%s\\n' "${FAKE_GIT_COMMON_DIR:?}"
    exit 0
fi

printf 'unexpected git invocation: %s\\n' "$*" >&2
exit 64
""",
                encoding="utf-8",
            )
            git.chmod(git.stat().st_mode | stat.S_IXUSR)

            environment = os.environ.copy()
            environment.pop("CRABC_WORK_DIR", None)
            environment.pop("CRABC_TARGET_VOLUME", None)
            environment.pop("CRABC_CARGO_VOLUME", None)
            environment.update(
                {
                    "CRABC_DEV_IMAGE": "crabc-test:aarch64",
                    "CRABC_CONTAINER_GIT_COMMON_DIR": str(untrusted_directory),
                    "FAKE_DOCKER_ARGS": str(capture),
                    "FAKE_GIT_COMMON_DIR": str(common_directory),
                    "PATH": f"{bin_directory}{os.pathsep}{environment['PATH']}",
                }
            )
            completed = subprocess.run(
                ["bash", str(DISPATCHER), "allocator", "--quick"],
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
            self.assertIn(
                ("--volume", f"{common_directory}:{common_directory}:ro"),
                argument_pairs,
            )
            self.assertNotIn(
                f"{untrusted_directory}:{untrusted_directory}:ro",
                arguments,
            )
            self.assertEqual(
                arguments[-3:],
                ["python3", "compat/allocator/run.py", "--quick"],
            )

    def test_structure_runs_in_pinned_container(self) -> None:
        """The structure gate must not depend on the host Python version."""

        with self._work_temporary_directory() as temporary:
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
            self.assertEqual(arguments[-2:], ["python3", "scripts/check_structure.py"])

    def test_dispatcher_runs_without_optional_oracle_mounts(self) -> None:
        """Optional oracle checkouts must not make the native dispatcher fail."""

        with self._work_temporary_directory() as temporary:
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

        with self._work_temporary_directory() as temporary:
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
            environment.pop("CRABC_WORK_DIR", None)
            environment.pop("CRABC_TARGET_VOLUME", None)
            environment.pop("CRABC_CARGO_VOLUME", None)
            environment.update(
                {
                    "CRABC_DEV_IMAGE": "crabc-test:aarch64",
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
