#!/usr/bin/env python3
"""Boundary contracts for the private native x86-64 allocator launcher."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "compat/allocator/run-x86_64.sh"
ROOT_DISPATCHER = ROOT / "scripts/dev.sh"


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
            "allocator-release-evidence",
            "allocator-aggregate-same-bin-still-live",
            "allocator-on-demand",
            "allocator-direct-on-demand",
            "allocator-regular-small",
            "allocator-medium-full-retire",
            "allocator-full-non-direct-small-force-collect-post-exit",
            "allocator-full-direct-small-force-collect-post-exit",
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
