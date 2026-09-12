#!/usr/bin/env python3
"""Contract for the owned x86 kernel-administration C ABI component."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "libc" / "Cargo.toml"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
RAW_SYSCALL = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
ARCH_SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "arch_prctl.rs"
IO_SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "io_permissions.rs"
PROBE = ROOT / "compat" / "x86_64" / "libc_kernel_admin_probe.c"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_kernel_admin.sh"
DOCUMENT = ROOT / "compat" / "x86_64" / "kernel-admin-abi.md"
README = ROOT / "compat" / "x86_64" / "README.md"


class KernelAdminAbiTests(unittest.TestCase):
    def test_owned_component_has_a_closed_provider_and_evidence_contract(self) -> None:
        for path in (ARCH_SOURCE, IO_SOURCE, PROBE, RUNNER, DOCUMENT):
            self.assertTrue(path.is_file(), f"missing kernel-admin input: {path}")
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        manifest = MANIFEST.read_text(encoding="utf-8")
        static_root = STATIC_ROOT.read_text(encoding="utf-8")
        raw_syscall = RAW_SYSCALL.read_text(encoding="utf-8")
        arch_source = ARCH_SOURCE.read_text(encoding="utf-8")
        io_source = IO_SOURCE.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        document = DOCUMENT.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")

        self.assertIn('x86-kernel-admin = ["x86-io-permissions"]', manifest)
        owned_start = manifest.index("x86-owned-static-runtime = [")
        owned_end = manifest.index("]\n# Share the owned leaf roster", owned_start)
        self.assertIn("x86-kernel-admin", manifest[owned_start:owned_end])
        self.assertIn(
            '#[cfg(feature = "x86-kernel-admin")]\n'
            '#[path = "arch_prctl.rs"]\n'
            "mod arch_prctl;",
            static_root,
        )
        self.assertIn(
            '#[cfg(any(feature = "x86-io-permissions", feature = "x86-kernel-admin"))]\n'
            '#[path = "io_permissions.rs"]\n'
            "mod io_permissions;",
            static_root,
        )
        self.assertIn("pub(crate) const SYS_ARCH_PRCTL: i64 = 158;", raw_syscall)

        for marker in (
            "src/linux/arch_prctl.c::arch_prctl",
            "syscall(SYS_arch_prctl, code, addr)",
            "SYS_ARCH_PRCTL",
            'pub unsafe extern "C" fn arch_prctl',
            "ARCH_GET_FS",
            "ARCH_GET_GS",
            "# Safety",
            "valid writable `unsigned long *`",
            "TLS and segment-base invariants",
            "performs no validation or recovery",
        ):
            self.assertIn(marker, arch_source)
        self.assertNotIn("ARCH_SET_FS", probe)
        self.assertNotIn("ARCH_SET_GS", probe)
        for marker in (
            "extern int arch_prctl(int, unsigned long);",
            "SYS_arch_prctl == 158",
            "ARCH_GET_FS",
            "ARCH_GET_GS",
            "ARCH_INVALID_OPERATION",
            "arch_prctl(ARCH_GET_FS, 0UL)",
            "arch_prctl(ARCH_GET_GS, 0UL)",
            "iopl_negative = observe_iopl_invalid(-1)",
            "ioperm_start = observe_ioperm_invalid(65536UL, 1UL, 0)",
        ):
            self.assertIn(marker, probe)
        self.assertNotIn("iopl(0)", probe)
        self.assertNotIn("ioperm(0UL, 1UL, 1)", probe)

        for marker in (
            "build_x86_64_owned_sysroot.py",
            "build_x86_64_owned_dynamic_sysroot.py",
            "assert_provider_symbols",
            "assert_provider_instructions",
            "static static-pie",
            "for mode in pie non-pie",
            "dynamic-$mode-kernel",
            "dynamic-$mode-direct",
            '"$work/$label.status"',
            "ARCH_GET_FS/GS",
            "TMPDIR must name checkout-local .work scratch",
            "-nostdinc -isystem",
            "arch_prctl)\n                immediate='\\$0x9e",
            "iopl)\n                immediate='\\$0xac",
            "ioperm)\n                immediate='\\$0xad",
            "raw $raw_helper_suffix helper",
        ):
            self.assertIn(marker, runner)
        for forbidden in ("--cap-add", "seccomp=", "--privileged", "inb", "outb"):
            self.assertNotIn(forbidden, runner)

        for marker in (
            "private native Linux/x86-64 foundation evidence",
            "x86-kernel-admin",
            "src/linux/arch_prctl.c::arch_prctl",
            "ARCH_GET_FS",
            "ARCH_GET_GS",
            "EINVAL`/`EPERM",
            "does not complete `system.kernel-admin`",
        ):
            self.assertIn(marker, document)
        self.assertIn("[kernel-admin-abi.md](kernel-admin-abi.md)", readme)


if __name__ == "__main__":
    unittest.main()
