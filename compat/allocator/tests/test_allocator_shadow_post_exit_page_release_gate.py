#!/usr/bin/env python3
"""Ratchet concurrent post-exit direct and C witnesses into the shadow gate."""

from __future__ import annotations

import shlex
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
DEV_SH = ROOT / "scripts/dev.sh"
DIRECT_TARGET = "native_concurrent_post_exit_page_release"
LIVE_DIRECT_TARGETS = (
    "native_live_remote_free",
    "native_two_live_remote_owners",
    "native_live_remote_owner_registry_reuse",
    "native_page_local_live_remote_protocol",
    "native_post_exit_claimed_remote_producers",
    "native_pointer_first_initial_foreign_free",
)
AUDIT_DIRECT_TARGETS = (
    "native_multiple_post_exit_completions",
    "native_terminal_completion_live_remote_free",
    "native_concurrent_post_exit_os_singletons",
    "native_concurrent_mixed_post_exit_completions",
    "native_persistent_worker_fastpath",
    "native_pointer_first_current_owner_reallocate",
    "native_pointer_first_usable_size",
    "native_owner_exit_collection_race",
    "native_ordinary_mapped_medium_reclaim",
)
RETIRED_ROUTE_TARGETS = (
    "native_post_exit_lifecycle",
    "native_sole_post_exit_lifecycle",
    "native_two_post_exit_lifecycle",
    "native_three_post_exit_lifecycle",
    "native_post_exit_with_local_session",
)
RETIRED_SESSION_TARGETS = (
    "runtime_lifecycle_session_initial_mapped_medium_post_exit_publisher",
    "runtime_lifecycle_session_post_exit_publisher",
    "runtime_lifecycle_session_post_exit_mapped_medium_publisher",
    "runtime_lifecycle_session_post_exit_mapped_medium_requires_publisher",
    "runtime_lifecycle_session_post_exit_mismatch_publisher",
)
RETIRED_HIGH_WATER_TARGETS = ("native_post_exit_registry_high_water",)
C_RELEASE_TARGET = "native_mimalloc_concurrent_post_exit_release"
C_RELEASE_FIXTURE = ROOT / "tests/fixtures/native_mimalloc_concurrent_post_exit_release_test.c"
C_RELEASE_HARNESS = ROOT / "tests/native_mimalloc_concurrent_post_exit_release.rs"
C_REALLOC_TARGET = "native_mimalloc_post_exit_concurrent_realloc"
C_REALLOC_FIXTURE = ROOT / "tests/fixtures/native_mimalloc_post_exit_concurrent_realloc_test.c"
C_REALLOC_HARNESS = ROOT / "tests/native_mimalloc_post_exit_concurrent_realloc.rs"
C_CONCURRENT_WITNESSES = (
    (C_RELEASE_TARGET, C_RELEASE_FIXTURE, C_RELEASE_HARNESS),
    (C_REALLOC_TARGET, C_REALLOC_FIXTURE, C_REALLOC_HARNESS),
)


def allocator_shadow_commands() -> list[list[str]]:
    """Return complete ``run_in_container`` commands from the shadow branch."""

    source = DEV_SH.read_text(encoding="utf-8")
    start = source.index("    allocator-shadow)")
    end = source.index("    allocator-tls)", start)
    branch = source[start:end]
    commands: list[list[str]] = []
    continued: list[str] | None = None

    for line in branch.splitlines():
        if continued is None:
            if not line.startswith("        run_in_container "):
                continue
            continued = []

        fragment = line.strip()
        if fragment.endswith("\\"):
            continued.append(fragment[:-1].rstrip())
            continue

        continued.append(fragment)
        commands.append(shlex.split(" ".join(continued)))
        continued = None

    if continued is not None:
        raise AssertionError("allocator-shadow ends with an unterminated command")
    return commands


def contains_tokens(command: list[str], expected: tuple[str, ...]) -> bool:
    """Require a contiguous token sequence, not a comment or unrelated lane."""

    width = len(expected)
    return any(command[index : index + width] == list(expected) for index in range(len(command)))


def selected_test_tokens(targets: tuple[str, ...]) -> list[str]:
    return [token for target in targets for token in ("--test", target)]


class AllocatorShadowPostExitGateTests(unittest.TestCase):
    def test_canonical_shadow_lane_reconciles_live_and_audit_direct_targets(self) -> None:
        commands = allocator_shadow_commands()
        direct_prefix = ("run_in_container", "cargo", "test", "-p", "crabc-mimalloc")
        live_commands = [
            command
            for command in commands
            if contains_tokens(command, direct_prefix)
            and contains_tokens(command, ("--test", LIVE_DIRECT_TARGETS[0]))
        ]
        self.assertEqual(live_commands, [
            [
                "run_in_container",
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                *selected_test_tokens(LIVE_DIRECT_TARGETS),
                "--",
                "--test-threads=1",
            ]
        ])

        audit_commands = [
            command
            for command in commands
            if contains_tokens(command, direct_prefix)
            and contains_tokens(command, ("--features", "native-runtime-test-audit"))
            and contains_tokens(command, ("--test", AUDIT_DIRECT_TARGETS[0]))
        ]
        self.assertEqual(audit_commands, [
            [
                "run_in_container",
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--features",
                "native-runtime-test-audit",
                *selected_test_tokens(AUDIT_DIRECT_TARGETS),
                "--",
                "--test-threads=1",
            ]
        ])

        for target in (
            *RETIRED_ROUTE_TARGETS,
            *RETIRED_SESSION_TARGETS,
            *RETIRED_HIGH_WATER_TARGETS,
        ):
            with self.subTest(retired_target=target):
                self.assertFalse(
                    any(contains_tokens(command, ("--test", target)) for command in commands)
                )

    def test_canonical_shadow_lane_selects_direct_and_concurrent_c_witnesses(self) -> None:
        commands = allocator_shadow_commands()
        direct_prefix = ("run_in_container", "cargo", "test", "-p", "crabc-mimalloc")
        direct_target = ("--test", DIRECT_TARGET)
        direct_commands = [
            command
            for command in commands
            if contains_tokens(command, direct_prefix) and contains_tokens(command, direct_target)
        ]
        self.assertEqual(direct_commands, [
            [
                "run_in_container",
                "cargo",
                "test",
                "-p",
                "crabc-mimalloc",
                "--test",
                "native_source_published_live_owner_exit",
                "--test",
                DIRECT_TARGET,
                "--",
                "--test-threads=1",
            ]
        ])

        selected_c_prefix = (
            "cargo",
            "test",
            "-q",
            "-p",
            "crabc-libc",
            "--features",
            "native-mimalloc-shadow",
        )
        selected_c_commands = [
            command for command in commands if contains_tokens(command, selected_c_prefix)
        ]
        self.assertEqual(len(selected_c_commands), 1)
        self.assertIn("--test-threads=1", selected_c_commands[0])

        for target, fixture, harness in C_CONCURRENT_WITNESSES:
            with self.subTest(target=target):
                self.assertTrue(contains_tokens(selected_c_commands[0], ("--test", target)))
                self.assertTrue(fixture.is_file())
                self.assertTrue(harness.is_file())
                self.assertIn(fixture.name, harness.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
