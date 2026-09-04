#!/usr/bin/env python3
"""Contracts for the opt-in native x86 POSIX spawn file-actions provider."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class X86LibcPosixSpawnFileActionsTests(unittest.TestCase):
    def test_raw_record_access_does_not_emit_rust_ub_panic_dependencies(self) -> None:
        implementation = (
            ROOT
            / "libc"
            / "src"
            / "c_abi"
            / "x86_64"
            / "posix_spawn_file_actions.rs"
        ).read_text(encoding="utf-8")

        for required in (
            "ptr::addr_of!((*file_actions).actions)",
            "ptr::addr_of_mut!((*operation).next).write(old_head)",
            "ptr::addr_of_mut!((*old_head).prev).write(operation)",
            "ptr::addr_of_mut!((*file_actions).actions).write",
            "ptr::read(path.cast::<u8>().add(index))",
            "ptr::write(destination.add(index), byte)",
        ):
            self.assertIn(required, implementation)
        self.assertNotIn("ptr::copy_nonoverlapping", implementation)

    def test_lifecycle_provider_uses_the_existing_mixed_allocator_boundary(self) -> None:
        runner = (
            ROOT / "compat" / "x86_64" / "run_libc_posix_spawn_file_actions.sh"
        ).read_text(encoding="utf-8")

        for required in (
            "mixed-runtime differential",
            "selected_archive",
            "action_members",
            "init_members",
            "allocator_members",
            "errno_members",
            "backend_members",
            'ar crs "$selected_archive"',
            '-Wl,-Map,"$link_map"',
            "pinned-musl allocator implementation",
            "pinned-musl file-actions implementation",
            "x86-posix-spawn-file-actions",
            "__crabc_x86_posix_spawn_file_actions_v1",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("-nostdlib", runner)
        self.assertNotIn("libc_posix_spawn_file_actions_start.S", runner)
        self.assertFalse(
            (ROOT / "compat" / "x86_64" / "libc_posix_spawn_file_actions_start.S").exists()
        )


if __name__ == "__main__":
    unittest.main()
