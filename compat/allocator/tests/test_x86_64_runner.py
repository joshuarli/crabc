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
            "allocator-cmake-modes",
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
