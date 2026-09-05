#!/usr/bin/env python3
"""Focused contracts for the owned x86 wordexp installed-product slice."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "libc/src/c_abi/x86_64/owned_wordexp.rs"
SCANNER = ROOT / "libc/src/wordexp_nocmd.rs"
PROBE = ROOT / "compat/x86_64/owned_wordexp_probe.c"
RUNNER = ROOT / "compat/x86_64/run_libc_owned_wordexp.sh"
DISPATCHER = ROOT / "scripts/dev-x86_64.sh"


class OwnedWordexpContracts(unittest.TestCase):
    def test_probe_has_source_mode_and_allocation_lifecycle_boundaries(self) -> None:
        source = PROBE.read_text(encoding="utf-8")
        for boundary in (
            "WRDE_DOOFFS | WRDE_APPEND", "WRDE_REUSE", "WRDE_NOCMD",
            "WRDE_CMDSUB", "WRDE_BADCHAR", "WRDE_SYNTAX", "WRDE_UNDEF",
            "check_freed", "owned-wordexp: PASS",
        ):
            self.assertIn(boundary, source)

    def test_module_uses_existing_spawn_and_stdio_ownership_seams(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        scanner = SCANNER.read_text(encoding="utf-8")
        self.assertIn("pinned musl 1.2.6", source)
        self.assertIn("owned_spawn::spawn", source)
        self.assertIn("stdio_standard::fdopen", source)
        self.assertIn("stdio_standard::getdelim", source)
        self.assertIn("stdio_standard::fclose", source)
        self.assertIn('include!("../../wordexp_nocmd.rs")', source)
        self.assertNotIn("sys_fork", source)
        self.assertNotIn("sys_execve", source)
        self.assertIn("wordexp_nocmd_check", scanner)

    def test_runner_preserves_default_boundary_and_proves_both_installed_modes(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        for boundary in (
            "frozen default archive unexpectedly exports",
            "--features x86-owned-static-runtime", "-static-pie",
            "pinned-musl wordexp oracle is not static ET_EXEC",
            "TMPDIR physically escapes checkout .work",
            "retained failure evidence", "run_installed_mode -static et-exec",
            "run_installed_mode -static-pie static-pie",
        ):
            self.assertIn(boundary, source)
        self.assertNotIn("--wrap=", source)

    def test_dispatcher_exposes_the_dedicated_native_gate(self) -> None:
        source = DISPATCHER.read_text(encoding="utf-8")
        self.assertIn("libc-owned-wordexp", source)
        self.assertIn("run_libc_owned_wordexp.sh", source)


if __name__ == "__main__":
    unittest.main()
