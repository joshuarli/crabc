#!/usr/bin/env python3
"""Focused contract for the selected x86 ``renameat2`` static C ABI leaf."""

from __future__ import annotations

import json
import stat
import subprocess
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
SOURCE = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "renameat2.rs"
SYSCALLS = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
STDIO = ROOT / "include" / "stdio.h"
C_HEADER_PROBE = ROOT / "compat" / "x86_64" / "renameat2_header_abi_probe.c"
CXX_HEADER_PROBE = ROOT / "compat" / "x86_64" / "renameat2_header_abi_probe.cpp"
HEADER_RUNNER = ROOT / "compat" / "x86_64" / "run_renameat2_header_abi.sh"
PROBE = ROOT / "compat" / "x86_64" / "libc_renameat2_probe.c"
START = ROOT / "compat" / "x86_64" / "libc_renameat2_start.S"
RUNNER = ROOT / "compat" / "x86_64" / "run_libc_renameat2.sh"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"
PARITY = ROOT / "compat" / "x86_64" / "parity.toml"
STATIC_EXPORTS = ROOT / "compat" / "x86_64" / "static_c_abi_exports.txt"
CALLABLE_INVENTORY = ROOT / "compat" / "x86_64" / "header_callable_inventory.json"


class Renameat2Tests(unittest.TestCase):
    def test_selected_static_leaf_preserves_musl_zero_flag_routing(self) -> None:
        for path in (
            SOURCE,
            C_HEADER_PROBE,
            CXX_HEADER_PROBE,
            HEADER_RUNNER,
            PROBE,
            START,
            RUNNER,
        ):
            self.assertTrue(path.is_file(), f"missing renameat2 input: {path}")
        for runner in (HEADER_RUNNER, RUNNER):
            self.assertEqual(stat.S_IMODE(runner.stat().st_mode), 0o755)
            syntax = subprocess.run(
                ["bash", "-n", str(runner)],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

        static_root = STATIC_ROOT.read_text(encoding="utf-8")
        source = SOURCE.read_text(encoding="utf-8")
        syscalls = SYSCALLS.read_text(encoding="utf-8")
        stdio = STDIO.read_text(encoding="utf-8")
        c_header_probe = C_HEADER_PROBE.read_text(encoding="utf-8")
        cxx_header_probe = CXX_HEADER_PROBE.read_text(encoding="utf-8")
        header_runner = HEADER_RUNNER.read_text(encoding="utf-8")
        probe = PROBE.read_text(encoding="utf-8")
        start = START.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        static_exports = STATIC_EXPORTS.read_text(encoding="utf-8").splitlines()
        ledger = tomllib.loads(PARITY.read_text(encoding="utf-8"))

        self.assertIn(
            '#[path = "renameat2.rs"]\nmod renameat2;', static_root
        )
        for required in (
            "Pinned musl 1.2.6",
            "src/linux/renameat2.c",
            "if (!flags) return syscall(SYS_renameat, oldfd, old, newfd, new);",
            "fn renameat2",
            "raw_syscall::SYS_RENAMEAT",
            "raw_syscall::SYS_RENAMEAT2",
            "raw_syscall::syscall4(",
            "raw_syscall::syscall5(",
            "c_status(result)",
            "# Safety",
        ):
            self.assertIn(required, source)
        for forbidden in ("fn renameat(", "crabc_core", "mimalloc", "alloc::", "Vec<"):
            self.assertNotIn(forbidden, source)
        self.assertIn("pub(crate) const SYS_RENAMEAT: i64 = 264;", syscalls)
        self.assertIn("pub(crate) const SYS_RENAMEAT2: i64 = 316;", syscalls)

        for required in (
            "#if defined(_GNU_SOURCE)",
            "#define RENAME_NOREPLACE (1 << 0)",
            "#define RENAME_EXCHANGE  (1 << 1)",
            "#define RENAME_WHITEOUT  (1 << 2)",
            "int renameat2(int, const char *, int, const char *, unsigned);",
        ):
            self.assertIn(required, stdio)
        for header_probe in (c_header_probe, cxx_header_probe):
            for required in (
                "renameat2_signature",
                "RENAME_NOREPLACE == 1",
                "RENAME_EXCHANGE == 2",
                "RENAME_WHITEOUT == 4",
                "CRABC_EXPECT_RENAMEAT2",
                "CRABC_REQUIRE_RENAMEAT2_HIDDEN",
            ):
                self.assertIn(required, header_probe)
        for required in (
            "EXPECTED_VISIBLE_PROFILE_COUNT=2",
            "EXPECTED_HIDDEN_PROFILE_COUNT=6",
            "cxx17-strict",
            "stdio.h",
            "renameat2",
            "unmangled",
            "-nostdinc",
            "-nostdinc++",
        ):
            self.assertIn(required, header_runner)

        for required in (
            "SYS_renameat == 264",
            "SYS_renameat2 == 316",
            "RENAME_NOREPLACE",
            "RENAME_EXCHANGE",
            "RENAME_WHITEOUT",
            "EEXIST",
            "EINVAL",
            "ENOENT",
            "CRABC_RENAMEAT2_FREESTANDING",
        ):
            self.assertIn(required, probe)
        self.assertIn("__crabc_x86_static_tls_bootstrap", start)
        self.assertNotIn("ARCH_SET_FS", start)
        for required in (
            "run_renameat2_header_abi.sh",
            "--gc-sections",
            "renameat2=316",
            "renameat=264",
            "candidate unexpectedly exports an independently selected pathname entry",
            "candidate lacks the musl zero-flag renameat branch",
            "candidate lacks the musl nonzero-flag renameat2 branch",
            "-nostdlib -static",
            "assert_selected_c_abi_surface",
        ):
            self.assertIn(required, runner)
        self.assertNotIn("--whole-archive", runner)

        self.assertIn("renameat2", static_exports)
        self.assertNotIn("renameat", static_exports)
        for required in (
            "renameat2-header-abi",
            "libc-renameat2",
            "run_renameat2_header_abi",
            "run_libc_renameat2_probe",
            "run_libc_renameat2.sh",
        ):
            self.assertIn(required, dispatcher)

        posix_runtime = next(
            family for family in ledger["family"] if family["id"] == "libc.posix-runtime"
        )
        artifact = next(
            record
            for record in posix_runtime["verified_artifact"]
            if record["id"] == "static-c-renameat2"
        )
        self.assertNotIn("capabilities", artifact)
        self.assertIn("renameat=264", artifact["description"])
        self.assertIn("renameat2=316", artifact["description"])
        self.assertIn("libc/src/c_abi/x86_64/renameat2.rs", artifact["source_owners"])
        self.assertIn("include/stdio.h", artifact["source_owners"])
        self.assertIn("compat/x86_64/run_libc_renameat2.sh", artifact["source_owners"])
        self.assertEqual(
            {"./scripts/dev-x86_64.sh libc-renameat2"},
            {evidence["command"] for evidence in artifact["native_evidence"]},
        )

    def test_callable_inventory_closes_the_three_oracle_visible_profiles(self) -> None:
        with CALLABLE_INVENTORY.open(encoding="utf-8") as stream:
            inventory = json.load(stream)

        expected_profiles = {"c11-gnu", "cxx17-gnu", "cxx17-strict"}
        callables = inventory["callables"]
        assert isinstance(callables, list)
        candidate = {
            record["profile"]: record
            for record in callables
            if record.get("tree") == "candidate"
            and record.get("classification") == "external"
            and record.get("name") == "renameat2"
        }
        reference = {
            record["profile"]: record
            for record in callables
            if record.get("tree") == "reference"
            and record.get("classification") == "external"
            and record.get("name") == "renameat2"
        }
        missing = [
            record
            for record in callables
            if record.get("classification") == "missing" and record.get("name") == "renameat2"
        ]

        self.assertEqual(set(candidate), expected_profiles)
        self.assertEqual(set(reference), expected_profiles)
        self.assertEqual(missing, [])
        for profile in expected_profiles:
            self.assertEqual(
                candidate[profile]["type"],
                "int (int, const char *, int, const char *, unsigned int)",
            )
            self.assertEqual(candidate[profile]["type"], reference[profile]["type"])
            self.assertIn("stdio.h", candidate[profile]["visible_from_headers"])
        self.assertNotIn(
            "renameat2", inventory["static_export_complement"]["members"]
        )


if __name__ == "__main__":
    unittest.main()
