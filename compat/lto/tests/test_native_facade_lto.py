#!/usr/bin/env python3
"""Focused host tests for the LTO evidence contract."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("native_facade_lto", ROOT / "compat/lto/native_facade_lto.py")
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


def witness_disassembly(*, public_branch: str = "") -> str:
    return f"""
0000000000001000 <{RUNNER.DEFAULT_ENTRY_SYMBOL}>:
    1000: mov w8, #0xac
    1004: svc #0
    1008: mov x8, #172
    100c: svc #0
{public_branch}
    1010: ret
0000000000001020 <route_write>:
    1020: mov w8, #0x40
    1024: svc #0
    1028: ret
"""


class NativeFacadeLtoInspectionTests(unittest.TestCase):
    def test_stock_std_runtime_loader_path_fits_the_musl_interpreter_slot(self) -> None:
        # Construct the small ELF portion `patched_interpreter_bytes` reads:
        # one 26-byte PT_INTERP slot, as emitted by the stock-std fixture.
        binary = bytearray(160)
        binary[:4] = b"\x7fELF"
        binary[4] = 2
        binary[5] = 1
        binary[18:20] = (183).to_bytes(2, "little")
        binary[32:40] = (64).to_bytes(8, "little")
        binary[54:56] = (56).to_bytes(2, "little")
        binary[56:58] = (1).to_bytes(2, "little")
        binary[64:68] = (3).to_bytes(4, "little")
        binary[72:80] = (128).to_bytes(8, "little")
        binary[96:104] = (26).to_bytes(8, "little")

        with tempfile.TemporaryDirectory(prefix=RUNNER.STOCK_STD_RUNTIME_PREFIX, dir="/tmp") as name:
            interpreter = str(Path(name) / "c")
            patched = RUNNER.patched_interpreter_bytes(bytes(binary), interpreter)

        expected = interpreter.encode("ascii") + b"\0"
        self.assertEqual(patched[128 : 128 + len(expected)], expected)

    def test_fixture_native_write_count_matches_its_payload(self) -> None:
        source = (ROOT / "compat/lto/native-facade-lto-fixture/src/main.rs").read_text()
        match = re.search(
            r'io::write\(&null, b"(?P<payload>[^"]*)"\) != Ok\((?P<count>\d+)\)',
            source,
        )
        self.assertIsNotNone(match)
        assert match is not None
        payload = bytes(match.group("payload"), "ascii").decode("unicode_escape").encode("ascii")
        self.assertEqual(int(match.group("count")), len(payload))

    def test_accepts_function_scoped_direct_getpid_and_write_paths(self) -> None:
        report = RUNNER.inspect_direct_route(
            readelf_text="Machine: AArch64\n",
            nm_text=f"0000000000001000 T {RUNNER.DEFAULT_ENTRY_SYMBOL}\n",
            disassembly=witness_disassembly(),
            entry_symbol=RUNNER.DEFAULT_ENTRY_SYMBOL,
        )
        self.assertTrue(report["witness_function_scoped"])
        self.assertTrue(report["witness_direct_getpid"])
        self.assertEqual(report["direct_syscalls"], {"getpid": True, "write": True})
        self.assertFalse(report["assembly_byte_exactness_claimed"])

    def test_rejects_public_wrapper_branch_inside_named_witness(self) -> None:
        with self.assertRaisesRegex(RUNNER.RunnerError, "forbidden public"):
            RUNNER.inspect_direct_route(
                readelf_text="Machine: AArch64\n",
                nm_text=f"0000000000001000 T {RUNNER.DEFAULT_ENTRY_SYMBOL}\n",
                disassembly=witness_disassembly(
                    public_branch="    1014: bl 0x2000 <getpid@plt>\n"
                ),
                entry_symbol=RUNNER.DEFAULT_ENTRY_SYMBOL,
            )

    def test_records_but_does_not_misattribute_unrelated_undefined_symbol(self) -> None:
        report = RUNNER.inspect_direct_route(
            readelf_text="Machine: AArch64\n",
            nm_text=(
                f"0000000000001000 T {RUNNER.DEFAULT_ENTRY_SYMBOL}\n"
                "                 U __errno_location\n"
            ),
            disassembly=witness_disassembly(),
            entry_symbol=RUNNER.DEFAULT_ENTRY_SYMBOL,
        )
        self.assertEqual(report["undefined_forbidden_symbols"], ["__errno_location"])

    def test_rejects_syscall_outside_witness_when_witness_has_no_getpid(self) -> None:
        disassembly = f"""
0000000000001000 <{RUNNER.DEFAULT_ENTRY_SYMBOL}>:
    1000: ret
0000000000001020 <other>:
    1020: mov w8, #0xac
    1024: svc #0
    1028: mov w8, #0x40
    102c: svc #0
"""
        with self.assertRaisesRegex(RUNNER.RunnerError, "witness lacks"):
            RUNNER.inspect_direct_route(
                readelf_text="Machine: AArch64\n",
                nm_text=f"0000000000001000 T {RUNNER.DEFAULT_ENTRY_SYMBOL}\n",
                disassembly=disassembly,
                entry_symbol=RUNNER.DEFAULT_ENTRY_SYMBOL,
            )

    def test_rlib_and_runtime_observations_are_not_byte_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "crabc-sysroot"
            owned = RUNNER.rustflags(
                lto="fat",
                dynamic=True,
                no_start_files=True,
                runtime=RUNNER.OWNED_SYSROOT_RUNTIME,
                sysroot=sysroot,
            )
        oracle = RUNNER.rustflags(
            lto="off",
            dynamic=True,
            no_start_files=True,
            runtime=RUNNER.MUSL_ORACLE_RUNTIME,
        )
        self.assertIn("-C lto=fat", owned)
        self.assertIn("-C link-self-contained=no", owned)
        self.assertIn("-l:libcrabc-builtins.a", owned)
        self.assertNotIn("/opt/musl-", owned)
        self.assertIn("-C lto=off", oracle)
        self.assertIn("/opt/musl-1.2.6", oracle)
        parsed = RUNNER.parse_syscall_summary(
            """
% time seconds usecs/call calls errors syscall
50.00 0.000010 5 2 0 getpid
50.00 0.000010 5 1 0 write
100.00 0.000020 5 3 0 total
"""
        )
        self.assertEqual(parsed["total_calls"], 3)

    def test_cargo_linker_audit_rejects_foreign_target_runtime_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record = Path(temporary) / "linker.jsonl"
            record.write_text(
                '["-L/opt/musl-1.2.6/lib", "-lgcc_s"]\n'
                '["-L/workspace/target/crabc-sysroot/usr/lib", "-lc"]\n',
                encoding="utf-8",
            )
            audit = RUNNER.cargo_linker_argument_audit(record)
        self.assertEqual(audit["status"], "rejected")
        self.assertEqual(
            audit["forbidden_target_runtime_arguments"],
            ["-L/opt/musl-1.2.6/lib", "-lgcc_s"],
        )

    def test_cargo_linker_audit_expands_recorded_response_file_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record = Path(temporary) / "linker.jsonl"
            record.write_text(
                json.dumps(
                    {
                        "argv": ["@/tmp/rustc-linker.rsp"],
                        "response_files": {"@/tmp/rustc-linker.rsp": ["-L/usr/lib/gcc/aarch64", "-lc"]},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            audit = RUNNER.cargo_linker_argument_audit(record)
        self.assertEqual(audit["status"], "rejected")
        self.assertEqual(audit["forbidden_target_runtime_arguments"], ["-L/usr/lib/gcc/aarch64"])

    def test_cargo_linker_audit_accepts_owned_sysroot_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record = Path(temporary) / "linker.jsonl"
            record.write_text(
                '["-L/workspace/target/crabc-sysroot/usr/lib", "-lc", "-l:libcrabc-builtins.a"]\n',
                encoding="utf-8",
            )
            audit = RUNNER.cargo_linker_argument_audit(record)
        self.assertEqual(audit["status"], "passed")
        self.assertEqual(audit["invocation_count"], 1)

    def test_owned_sysroot_contract_requires_the_sealed_runtime_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sysroot = Path(temporary) / "crabc-sysroot"
            (sysroot / "bin").mkdir(parents=True)
            (sysroot / "lib").mkdir()
            (sysroot / "usr/lib").mkdir(parents=True)
            (sysroot / "share/crabc").mkdir(parents=True)
            (sysroot / "share/crabc/manifest.json").write_text(
                json.dumps(
                    {
                        "target": RUNNER.TARGET,
                        "canonical_interpreter": RUNNER.CANONICAL_INTERPRETER,
                    }
                ),
                encoding="utf-8",
            )
            (sysroot / "share/crabc/purity.json").write_text(
                json.dumps({"crt_sysroot_pure_rust": True}), encoding="utf-8"
            )
            driver = sysroot / "bin/crabc-cc"
            driver.write_text("#!/bin/sh\n", encoding="utf-8")
            driver.chmod(0o755)
            (sysroot / "lib/ld-crabc-aarch64.so.1").write_bytes(b"loader")
            for name in ("libc.so", "libc.a", "libcrabc-builtins.a", "crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o"):
                (sysroot / "usr/lib" / name).write_bytes(name.encode())
            self.assertEqual(RUNNER.owned_sysroot_reasons(sysroot), [])
            (sysroot / "usr/lib/libcrabc-builtins.a").unlink()
            reasons = RUNNER.owned_sysroot_reasons(sysroot)
        self.assertIn("libcrabc-builtins.a", "\n".join(reasons))


if __name__ == "__main__":
    unittest.main()
