#!/usr/bin/env python3
"""Source, provider, and harness contracts for owned Unix C mechanisms."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "owned_unix_mechanisms.rs"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
SYSCALL = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
QUALIFICATION = ROOT / "compat" / "x86_64" / "owned_dynamic_qualification.py"
RUNNER = ROOT / "compat" / "x86_64" / "run_owned_unix_mechanisms.sh"
PROBE = ROOT / "compat" / "x86_64" / "owned_unix_mechanisms_probe.c"


class OwnedUnixMechanismTests(unittest.TestCase):
    def test_owned_module_is_the_selected_eight_symbol_provider(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        for name in (
            "get_current_dir_name",
            "mount",
            "umount",
            "umount2",
            "tcdrain",
            "vhangup",
            "vmsplice",
            "isastream",
        ):
            self.assertIn(f'fn {name}(', source)

        root = STATIC_ROOT.read_text(encoding="utf-8")
        self.assertIn(
            '#[cfg(feature = "x86-owned-static-runtime")]\n'
            '#[path = "owned_unix_mechanisms.rs"]\n'
            "mod owned_unix_mechanisms;",
            root,
        )

    def test_source_mapping_preserves_getcwd_cancellation_and_linux_boundaries(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        for required in (
            "src/misc/get_current_dir_name.c",
            "src/linux/mount.c",
            "src/termios/tcdrain.c",
            "src/linux/vhangup.c",
            "src/linux/vmsplice.c",
            "src/legacy/isastream.c",
            "pathname_lifecycle::getcwd",
            "allocator_string_duplication::strdup",
            "super::pthread_cancel::syscall_cp",
            "raw_syscall::SYS_IOCTL",
            "raw_syscall::SYS_MOUNT",
            "raw_syscall::SYS_UMOUNT2",
            "raw_syscall::SYS_VHANGUP",
            "raw_syscall::SYS_VMSPLICE",
            "F_GETFD",
        ):
            self.assertIn(required, source)

        syscall = SYSCALL.read_text(encoding="utf-8")
        for required in (
            "pub(crate) const SYS_VHANGUP: i64 = 153;",
            "pub(crate) const SYS_MOUNT: i64 = 165;",
            "pub(crate) const SYS_UMOUNT2: i64 = 166;",
            "pub(crate) const SYS_VMSPLICE: i64 = 278;",
        ):
            self.assertIn(required, syscall)

    def test_dynamic_qualification_replays_the_same_object_runner(self) -> None:
        source = QUALIFICATION.read_text(encoding="utf-8")
        self.assertIn(
            '"unix-mechanisms": ("run_owned_unix_mechanisms.sh", None)',
            source,
        )

    def test_runner_contains_contained_privileged_and_terminal_evidence(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for required in (
            "provided_dynamic",
            "assert_mechanism_symbols",
            "terminal-cancel",
            "vmsplice",
            "run_in_root",
            "static static-pie",
            "kernel/direct",
        ):
            self.assertIn(required, source)
        self.assertEqual(source.count("if [ -z \"$provided_dynamic\" ]; then"), 1)
        self.assertIn('if [ "${1:-}" = "" ]; then', source)

        probe = PROBE.read_text(encoding="utf-8")
        for required in (
            "SECCOMP_RET_ERRNO | EPERM",
            "SYS_mount",
            "SYS_umount2",
            "SYS_vhangup",
        ):
            self.assertIn(required, probe)

    def test_supplied_product_escape_is_rejected_before_building(self) -> None:
        scratch_root = ROOT / ".work/x86_64/tmp"
        scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
            result = subprocess.run(
                ["bash", str(RUNNER), str(ROOT)],
                env={**os.environ, "TMPDIR": temporary},
                text=True,
                capture_output=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "owned unix mechanisms product must be a checkout .work directory",
            result.stderr,
        )
        self.assertNotIn("evidence:", result.stdout)


if __name__ == "__main__":
    unittest.main()
