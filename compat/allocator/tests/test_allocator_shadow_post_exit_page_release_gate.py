#!/usr/bin/env python3
"""Ratchet concurrent post-exit release witnesses into the shadow gate."""

from __future__ import annotations

import shlex
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
DEV_SH = ROOT / "scripts/dev.sh"
DIRECT_TARGET = "native_concurrent_post_exit_page_release"
C_TARGET = "native_mimalloc_concurrent_post_exit_release"
C_FIXTURE = ROOT / "tests/fixtures/native_mimalloc_concurrent_post_exit_release_test.c"
C_HARNESS = ROOT / "tests/native_mimalloc_concurrent_post_exit_release.rs"


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


class AllocatorShadowPostExitPageReleaseGateTests(unittest.TestCase):
    def test_canonical_shadow_lane_selects_both_concurrent_release_witnesses(self) -> None:
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
        self.assertTrue(contains_tokens(selected_c_commands[0], ("--test", C_TARGET)))
        self.assertIn("--test-threads=1", selected_c_commands[0])

        self.assertTrue(C_FIXTURE.is_file())
        self.assertTrue(C_HARNESS.is_file())
        self.assertIn(C_FIXTURE.name, C_HARNESS.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
