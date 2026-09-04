#!/usr/bin/env python3
"""Boundary contracts for the private native x86-64 allocator launcher."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/allocator/run-x86_64.sh"
ROOT_DISPATCHER = ROOT / "scripts/dev.sh"


class X86AllocatorWorkspaceTests(unittest.TestCase):
    """Execute the real launcher with inert Docker in a disposable checkout."""

    def setUp(self) -> None:
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name)
        self.checkout = self.fixture / "checkout"
        self.launcher = self.checkout / "compat/allocator/run-x86_64.sh"
        self.launcher.parent.mkdir(parents=True)
        self.launcher.write_text(RUNNER.read_text())
        self.boundary = self.checkout / ".work/allocator-x86_64"
        self.capture = self.fixture / "docker-args"
        self.bin = self.fixture / "bin"
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text('''#!/usr/bin/env bash
set -eu
printf '%s\\n' "$1" >> "$DOCKER_CAPTURE.calls"
if [ "$1" = image ]; then
    if [ "${3:-}" = --format ]; then printf 'linux/amd64\\n'; fi
elif [ "$1" = run ]; then
    printf '%s\\0' "$@" > "$DOCKER_CAPTURE"
fi
''')
        docker.chmod(0o755)
        uname = self.bin / "uname"
        uname.write_text("#!/bin/sh\nprintf 'x86_64\\n'\n")
        uname.chmod(0o755)

    def launch(self, *arguments: str, work: str | None = None):
        env = os.environ.copy()
        env.pop("CRABC_ALLOCATOR_X86_64_WORK_DIR", None)
        if work is not None:
            env["CRABC_ALLOCATOR_X86_64_WORK_DIR"] = work
        env.update(PATH=f"{self.bin}:{env['PATH']}", DOCKER_CAPTURE=str(self.capture))
        return subprocess.run(
            ["bash", str(self.launcher), *arguments], cwd=self.checkout,
            env=env, text=True, capture_output=True,
        )

    def test_native_commands_bind_all_mutable_state_to_the_checkout(self):
        for command in (("allocator", "--quick"), ("allocator-m1",), ("allocator-m2",), ("allocator-unit",),
                        ("allocator-release-evidence",), ("allocator-perf", "--smoke")):
            with self.subTest(command=command):
                result = self.launch(*command)
                self.assertEqual(result.returncode, 0, result.stderr)
                args = self.capture.read_bytes().split(b"\0")
                for source, target in (
                    ("", "/workspace/.work/allocator-x86_64"),
                    ("target", "/workspace/target"),
                    ("reports", "/workspace/compat/reports"),
                    ("allocator-cache", "/workspace/compat/allocator/.cache"),
                    ("tmp", "/tmp"),
                ):
                    self.assertIn(f"{self.boundary / source}:{target}".encode(), args)
                for name, suffix in (("CARGO_HOME", "/cargo"), ("TMPDIR", "/tmp"),
                                     ("CRABC_WORK_DIR", "")):
                    self.assertIn(f"{name}=/workspace/.work/allocator-x86_64{suffix}".encode(), args)
                self.assertNotIn(b"CARGO_HOME=/opt/cargo", args)
                self.assertFalse(any(arg.endswith(b":/opt/cargo") for arg in args))

    def test_accepts_a_physical_descendant_override(self):
        work = self.boundary / "worker with spaces"
        result = self.launch("allocator", "--quick", work=str(work))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"{work}:/workspace/.work/allocator-x86_64".encode(),
                      self.capture.read_bytes().split(b"\0"))

    def test_rejects_external_named_traversal_and_mount_syntax_before_docker(self):
        for work in (str(self.fixture / "outside"), "named-volume", "../outside",
                     str(self.boundary / "../escape"), str(self.boundary) + ":/override"):
            with self.subTest(work=work):
                result = self.launch("allocator", "--quick", work=work)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.capture.with_suffix(".calls").exists())

    def test_rejects_symlink_escapes_before_docker_or_directory_creation(self):
        outside = self.fixture / "outside"
        outside.mkdir()
        for suffix in (".work", ".work/allocator-x86_64",
                       ".work/allocator-x86_64/target", ".work/allocator-x86_64/cargo",
                       ".work/allocator-x86_64/tmp", ".work/allocator-x86_64/reports",
                       ".work/allocator-x86_64/allocator-cache"):
            with self.subTest(suffix=suffix):
                link = self.checkout / suffix
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(outside, target_is_directory=True)
                result = self.launch("allocator", "--quick")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.capture.with_suffix(".calls").exists())
                self.assertEqual(list(outside.iterdir()), [])
                link.unlink()

    def test_linked_worktree_mounts_actual_readonly_git_metadata_without_git_env(self):
        repository = self.fixture / "repository"
        repository.mkdir()
        subprocess.run(
            ["git", "init", "--initial-branch=main", str(repository)],
            check=True,
            text=True,
            capture_output=True,
        )
        for key, value in (("user.email", "allocator@example.invalid"), ("user.name", "Allocator")):
            subprocess.run(
                ["git", "-C", str(repository), "config", key, value],
                check=True,
                text=True,
                capture_output=True,
            )
        (repository / "README").write_text("linked-worktree fixture\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repository), "add", "README"],
            check=True,
            text=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(repository), "commit", "-m", "fixture"],
            check=True,
            text=True,
            capture_output=True,
        )
        linked = self.fixture / "linked-worktree"
        subprocess.run(
            ["git", "-C", str(repository), "worktree", "add", "-b", "linked", str(linked)],
            check=True,
            text=True,
            capture_output=True,
        )
        launcher = linked / "compat/allocator/run-x86_64.sh"
        launcher.parent.mkdir(parents=True)
        launcher.write_text(RUNNER.read_text(encoding="utf-8"), encoding="utf-8")
        environment = os.environ.copy()
        environment.update(PATH=f"{self.bin}:{environment['PATH']}", DOCKER_CAPTURE=str(self.capture))
        result = subprocess.run(
            ["bash", str(launcher), "allocator", "--quick"],
            cwd=linked,
            env=environment,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = self.capture.read_bytes().split(b"\0")
        common = subprocess.run(
            ["git", "-C", str(linked), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        self.assertIn(f"{common}:{common}:ro".encode(), arguments)
        self.assertIn(f"{linked}:{linked}:ro".encode(), arguments)
        self.assertNotIn(b"GIT_DIR=", arguments)
        self.assertNotIn(b"GIT_WORK_TREE=", arguments)

    def test_help_and_invalid_commands_create_no_workspace_or_docker_state(self):
        for args, expected in ((("--help",), 0), (("shell",), 2),
                               (("allocator", "--full"), 2)):
            result = self.launch(*args)
            self.assertEqual(result.returncode, expected, result.stderr)
        self.assertFalse((self.checkout / ".work").exists())
        self.assertFalse(self.capture.with_suffix(".calls").exists())


class X86_64RunnerBoundaryTests(unittest.TestCase):
    def run_launcher(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(RUNNER), *arguments],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_script_is_valid_and_exposes_only_private_allocator_commands(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        source = RUNNER.read_text(encoding="utf-8")
        for command in (
            "allocator --quick",
            "allocator-m1",
            "allocator-m2",
            "allocator-release-evidence",
            "allocator-cmake-modes",
            "allocator-live-owner-full-medium-remote-release",
            "allocator-mapped-adoption",
            "allocator-direct-small-allocation-adoption",
            "allocator-aggregate-same-bin-still-live",
            "allocator-on-demand",
            "allocator-direct-on-demand",
            "allocator-aligned-overalloc-realloc",
            "allocator-regular-small",
            "allocator-direct-small-full-retire",
            "allocator-medium-full-retire",
            "allocator-full-non-direct-small-force-collect-post-exit",
            "allocator-full-direct-small-force-collect-post-exit",
            "allocator-dynamic-full-direct-small-one-remote-force-collect-to-mapped",
            "allocator-dynamic-full-direct-small-unmapped-reabandon",
            "allocator-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped",
            "allocator-dynamic-full-non-direct-small-unmapped-reabandon",
            "allocator-dynamic-full-medium-one-remote-force-collect-to-mapped",
            "allocator-dynamic-full-medium-unmapped-reabandon",
            "allocator-dynamic-full-large-one-remote-force-collect-to-mapped",
            "allocator-dynamic-full-large-homogeneous-aggregate",
            "allocator-dynamic-full-medium-homogeneous-aggregate",
            "allocator-dynamic-full-singleton-homogeneous-aggregate",
            "allocator-dynamic-full-non-direct-small-homogeneous-aggregate",
            "allocator-later-thread-exit-full-direct-small-pages",
            "allocator-dynamic-nonfull-regular-pages-distinct-bin-aggregate",
            "allocator-dynamic-os-aligned-singleton",
            "allocator-dynamic-arena-singleton-post-exit",
            "allocator-unit",
            "allocator-core-unit",
        ):
            self.assertIn(command, source)
        self.assertIn("CRABC_EXECUTION_MODE=native", source)
        self.assertIn("CRABC_HOST_ARCH=x86_64", source)
        self.assertIn("linux/amd64", source)
        self.assertNotIn('"$ROOT_DIR/scripts/dev.sh"', source)
        self.assertNotIn('cargo "$@"', source)
        self.assertNotIn("crabc-libc", source)

    def test_m1_command_is_closed_and_selects_the_native_x86_gate(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-m1)", source)
        self.assertIn(
            "run_in_container python3 compat/allocator/run.py --m1 --offline",
            source,
        )
        result = self.run_launcher("allocator-m1", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn("allocator-m1 takes no arguments", result.stderr)

    def test_m2_command_is_closed_and_selects_the_native_x86_gate(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-m2)", source)
        self.assertIn(
            "run_in_container python3 compat/allocator/run.py --m2 --offline",
            source,
        )
        result = self.run_launcher("allocator-m2", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn("allocator-m2 takes no arguments", result.stderr)

    def test_every_native_dispatch_uses_a_fresh_python_bytecode_environment(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        container_function = source.split("run_in_container() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn("--env PYTHONDONTWRITEBYTECODE=1", container_function)
        dispatch = source.split('case "$command" in', 2)[-1]
        self.assertGreater(dispatch.count("run_in_container "), 0)
        self.assertEqual(
            dispatch.count("run_in_container "),
            source.count("run_in_container "),
        )

    def test_linked_worktree_git_metadata_is_visible_read_only_without_global_git_env(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("linked_worktree_git_mounts()", source)
        self.assertIn("git -C \"$ROOT_DIR\" rev-parse --path-format=absolute --git-common-dir", source)
        self.assertIn("git -C \"$ROOT_DIR\" rev-parse --path-format=absolute --git-dir", source)
        self.assertIn('"$physical_common_dir:$physical_common_dir:ro"', source)
        self.assertIn('"$ROOT_DIR:$ROOT_DIR:ro"', source)
        self.assertIn('"${GIT_METADATA_MOUNTS[@]}"', source)
        self.assertNotIn("--env GIT_DIR=", source)
        self.assertNotIn("--env GIT_WORK_TREE=", source)

    def test_cmake_modes_command_is_closed_and_uses_its_private_offline_probe(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-cmake-modes)", source)
        self.assertIn(
            "run_in_container python3 compat/allocator/x86_64_cmake_mode_evidence.py --offline",
            source,
        )
        result = self.run_launcher("allocator-cmake-modes", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn("allocator-cmake-modes takes no arguments", result.stderr)

    def test_live_owner_full_medium_remote_release_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-live-owner-full-medium-remote-release)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_live_owner_full_medium_remote_release_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-live-owner-full-medium-remote-release", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-live-owner-full-medium-remote-release takes no arguments",
            result.stderr,
        )

    def test_live_owner_full_medium_one_remote_unfull_reuse_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-live-owner-full-medium-one-remote-unfull-reuse)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_live_owner_full_medium_one_remote_unfull_reuse_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-live-owner-full-medium-one-remote-unfull-reuse", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-live-owner-full-medium-one-remote-unfull-reuse takes no arguments",
            result.stderr,
        )

    def test_mapped_adoption_command_is_closed_and_uses_its_private_offline_probe(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-mapped-adoption)", source)
        self.assertIn(
            "run_in_container python3 compat/allocator/x86_64_mapped_adoption_evidence.py --offline",
            source,
        )
        result = self.run_launcher("allocator-mapped-adoption", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn("allocator-mapped-adoption takes no arguments", result.stderr)

    def test_direct_small_allocation_adoption_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-direct-small-allocation-adoption)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_direct_small_allocation_adoption_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-direct-small-allocation-adoption", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-direct-small-allocation-adoption takes no arguments",
            result.stderr,
        )

    def test_on_demand_command_is_closed_and_uses_its_private_offline_probe(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-on-demand)", source)
        self.assertIn(
            "run_in_container python3 compat/allocator/x86_64_on_demand_evidence.py --offline",
            source,
        )

        result = self.run_launcher("allocator-on-demand", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn("allocator-on-demand takes no arguments", result.stderr)

    def test_direct_on_demand_command_is_closed_and_uses_its_private_offline_probe(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-direct-on-demand)", source)
        self.assertIn(
            "run_in_container python3 compat/allocator/x86_64_direct_on_demand_evidence.py --offline",
            source,
        )

        result = self.run_launcher("allocator-direct-on-demand", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn("allocator-direct-on-demand takes no arguments", result.stderr)

    def test_aligned_overalloc_realloc_command_is_closed_and_uses_its_private_offline_probe(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-aligned-overalloc-realloc)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_aligned_overalloc_realloc_evidence.py --offline",
            source,
        )
        result = self.run_launcher("allocator-aligned-overalloc-realloc", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn("allocator-aligned-overalloc-realloc takes no arguments", result.stderr)

    def test_regular_small_command_is_closed_and_uses_its_private_offline_probe(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-regular-small)", source)
        self.assertIn(
            "run_in_container python3 compat/allocator/x86_64_regular_small_evidence.py --offline",
            source,
        )

        result = self.run_launcher("allocator-regular-small", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn("allocator-regular-small takes no arguments", result.stderr)

    def test_direct_small_full_retire_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-direct-small-full-retire)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_direct_small_full_retire_evidence.py --offline",
            source,
        )

        result = self.run_launcher("allocator-direct-small-full-retire", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-direct-small-full-retire takes no arguments",
            result.stderr,
        )

    def test_medium_full_retire_command_is_closed_and_uses_its_private_offline_probe(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-medium-full-retire)", source)
        self.assertIn(
            "run_in_container python3 compat/allocator/x86_64_medium_full_retire_evidence.py --offline",
            source,
        )
        result = self.run_launcher("allocator-medium-full-retire", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn("allocator-medium-full-retire takes no arguments", result.stderr)

    def test_full_non_direct_small_force_collect_post_exit_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-full-non-direct-small-force-collect-post-exit)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_full_non_direct_small_force_collect_post_exit_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-full-non-direct-small-force-collect-post-exit", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-full-non-direct-small-force-collect-post-exit takes no arguments",
            result.stderr,
        )

    def test_full_direct_small_force_collect_post_exit_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-full-direct-small-force-collect-post-exit)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_full_direct_small_force_collect_post_exit_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-full-direct-small-force-collect-post-exit", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-full-direct-small-force-collect-post-exit takes no arguments",
            result.stderr,
        )

    def test_dynamic_full_medium_one_remote_force_collect_to_mapped_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn(
            "allocator-dynamic-full-medium-one-remote-force-collect-to-mapped)",
            source,
        )
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_full_medium_one_remote_force_collect_to_mapped_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-full-medium-one-remote-force-collect-to-mapped", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-full-medium-one-remote-force-collect-to-mapped takes no arguments",
            result.stderr,
        )

    def test_dynamic_full_medium_unmapped_reabandon_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-dynamic-full-medium-unmapped-reabandon)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_full_medium_unmapped_reabandon_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-full-medium-unmapped-reabandon", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-full-medium-unmapped-reabandon takes no arguments",
            result.stderr,
        )

    def test_dynamic_full_direct_small_one_remote_force_collect_to_mapped_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn(
            "allocator-dynamic-full-direct-small-one-remote-force-collect-to-mapped)",
            source,
        )
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_full_direct_small_one_remote_force_collect_to_mapped_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-full-direct-small-one-remote-force-collect-to-mapped",
            "unexpected",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-full-direct-small-one-remote-force-collect-to-mapped takes no arguments",
            result.stderr,
        )

    def test_dynamic_full_direct_small_unmapped_reabandon_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn(
            "allocator-dynamic-full-direct-small-unmapped-reabandon)",
            source,
        )
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_full_direct_small_unmapped_reabandon_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-full-direct-small-unmapped-reabandon",
            "unexpected",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-full-direct-small-unmapped-reabandon takes no arguments",
            result.stderr,
        )

    def test_dynamic_full_non_direct_small_one_remote_force_collect_to_mapped_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn(
            "allocator-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped)",
            source,
        )
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_full_non_direct_small_one_remote_force_collect_to_mapped_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped",
            "unexpected",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-full-non-direct-small-one-remote-force-collect-to-mapped takes no arguments",
            result.stderr,
        )

    def test_dynamic_full_non_direct_small_unmapped_reabandon_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn(
            "allocator-dynamic-full-non-direct-small-unmapped-reabandon)",
            source,
        )
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_full_non_direct_small_unmapped_reabandon_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-full-non-direct-small-unmapped-reabandon",
            "unexpected",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-full-non-direct-small-unmapped-reabandon takes no arguments",
            result.stderr,
        )

    def test_later_thread_exit_full_direct_small_pages_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn(
            "allocator-later-thread-exit-full-direct-small-pages)",
            source,
        )
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_later_thread_exit_full_direct_small_pages_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-later-thread-exit-full-direct-small-pages",
            "unexpected",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-later-thread-exit-full-direct-small-pages takes no arguments",
            result.stderr,
        )

    def test_dynamic_full_large_one_remote_force_collect_to_mapped_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-dynamic-full-large-one-remote-force-collect-to-mapped)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_full_large_one_remote_force_collect_to_mapped_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-full-large-one-remote-force-collect-to-mapped", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-full-large-one-remote-force-collect-to-mapped takes no arguments",
            result.stderr,
        )

    def test_dynamic_full_large_unmapped_reabandon_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-dynamic-full-large-unmapped-reabandon)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_full_large_unmapped_reabandon_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-full-large-unmapped-reabandon", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-full-large-unmapped-reabandon takes no arguments",
            result.stderr,
        )

    def test_dynamic_full_large_homogeneous_aggregate_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-dynamic-full-large-homogeneous-aggregate)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_full_large_homogeneous_aggregate_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-full-large-homogeneous-aggregate", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-full-large-homogeneous-aggregate takes no arguments",
            result.stderr,
        )

    def test_dynamic_full_medium_homogeneous_aggregate_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-dynamic-full-medium-homogeneous-aggregate)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_full_medium_homogeneous_aggregate_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-full-medium-homogeneous-aggregate", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-full-medium-homogeneous-aggregate takes no arguments",
            result.stderr,
        )

    def test_dynamic_full_singleton_homogeneous_aggregate_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-dynamic-full-singleton-homogeneous-aggregate)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_full_singleton_homogeneous_aggregate_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-full-singleton-homogeneous-aggregate", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-full-singleton-homogeneous-aggregate takes no arguments",
            result.stderr,
        )

    def test_dynamic_full_non_direct_small_homogeneous_aggregate_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-dynamic-full-non-direct-small-homogeneous-aggregate)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_full_non_direct_small_homogeneous_aggregate_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-full-non-direct-small-homogeneous-aggregate", "unexpected"
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-full-non-direct-small-homogeneous-aggregate takes no arguments",
            result.stderr,
        )

    def test_dynamic_nonfull_regular_pages_distinct_bin_aggregate_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn(
            "allocator-dynamic-nonfull-regular-pages-distinct-bin-aggregate)",
            source,
        )
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_nonfull_regular_pages_distinct_bin_aggregate_evidence.py "
            "--offline",
            source,
        )
        result = self.run_launcher(
            "allocator-dynamic-nonfull-regular-pages-distinct-bin-aggregate",
            "unexpected",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-nonfull-regular-pages-distinct-bin-aggregate takes no arguments",
            result.stderr,
        )

    def test_automatic_pthread_destructor_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-automatic-pthread-destructor)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_automatic_pthread_destructor_evidence.py --offline",
            source,
        )
        result = self.run_launcher("allocator-automatic-pthread-destructor", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-automatic-pthread-destructor takes no arguments",
            result.stderr,
        )

    def test_cancellation_pthread_destructor_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-cancellation-pthread-destructor)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_cancellation_pthread_destructor_evidence.py --offline",
            source,
        )
        result = self.run_launcher("allocator-cancellation-pthread-destructor", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-cancellation-pthread-destructor takes no arguments",
            result.stderr,
        )

    def test_dynamic_os_aligned_singleton_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-dynamic-os-aligned-singleton)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_os_aligned_singleton_evidence.py --offline",
            source,
        )
        result = self.run_launcher("allocator-dynamic-os-aligned-singleton", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-os-aligned-singleton takes no arguments",
            result.stderr,
        )

    def test_dynamic_arena_singleton_post_exit_command_is_closed_and_uses_its_private_offline_probe(
        self,
    ) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("allocator-dynamic-arena-singleton-post-exit)", source)
        self.assertIn(
            "run_in_container python3 "
            "compat/allocator/x86_64_dynamic_arena_singleton_post_exit_evidence.py --offline",
            source,
        )
        result = self.run_launcher("allocator-dynamic-arena-singleton-post-exit", "unexpected")
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "allocator-dynamic-arena-singleton-post-exit takes no arguments",
            result.stderr,
        )

    def test_help_and_unsupported_command_do_not_need_docker(self) -> None:
        help_result = self.run_launcher("--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("Private native Linux/x86-64", help_result.stdout)
        self.assertIn("does not provide x86 crabc runtime", help_result.stdout)

        unsupported = self.run_launcher("build")
        self.assertEqual(unsupported.returncode, 2)
        self.assertIn("Usage:", unsupported.stderr)

    def test_root_dispatcher_remains_aarch64_only(self) -> None:
        source = ROOT_DISPATCHER.read_text(encoding="utf-8")
        self.assertIn('readonly PLATFORM="linux/arm64"', source)
        self.assertNotIn("allocator-remote-free", source)
        self.assertFalse((ROOT / "scripts/dev-amd64.sh").exists())


if __name__ == "__main__":
    unittest.main()
