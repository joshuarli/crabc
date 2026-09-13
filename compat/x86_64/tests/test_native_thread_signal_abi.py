#!/usr/bin/env python3
"""Focused contract tests for the native x86 `tgkill` C ABI component."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
HEADER = ROOT / "include" / "signal.h"
STATIC_ROOT = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "static_c_abi.rs"
RAW_SYSCALL = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "syscall.rs"
PROVIDER = ROOT / "libc" / "src" / "c_abi" / "x86_64" / "thread_signal.rs"
PROBE = ROOT / "compat" / "x86_64" / "native_thread_signal_abi_probe.c"
ADAPTER = ROOT / "compat" / "x86_64" / "native_thread_signal_oracle_adapter.c"
CPP_GNU_PROBE = ROOT / "compat" / "x86_64" / "native_thread_signal_header_gnu.cc"
CPP_STRICT_PROBE = ROOT / "compat" / "x86_64" / "native_thread_signal_header_strict.cc"
CONTRACT = ROOT / "compat" / "x86_64" / "native_thread_signal_abi.json"
READER = ROOT / "compat" / "x86_64" / "native_thread_signal_abi_symbols.py"
RUNNER = ROOT / "compat" / "x86_64" / "run_native_thread_signal_abi.sh"
DOCUMENT = ROOT / "compat" / "x86_64" / "native-thread-signal-abi.md"
README = ROOT / "compat" / "x86_64" / "README.md"


spec = importlib.util.spec_from_file_location("native_thread_signal_abi_symbols", READER)
assert spec and spec.loader
symbols = importlib.util.module_from_spec(spec)
spec.loader.exec_module(symbols)


class NativeThreadSignalAbiTests(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def _row(index: int, value: int, size: int, kind: str, binding: str, visibility: str,
             section: str, name: str) -> str:
        return (
            f"{index:6}: {value:016x} {size:5} {kind:<7} {binding:<6} {visibility:<7} "
            f"{section:>5} {name}\n"
        )

    def _table(self, table: str, *, archive: bool, candidate: bool,
               broken: str | None = None) -> str:
        entries: list[tuple[int, int, int, str, str, str, str, str]] = [
            (0, 0, 0, "NOTYPE", "LOCAL", "DEFAULT", "UND", ""),
        ]
        if candidate:
            binding = "WEAK" if broken == "weak" else "GLOBAL"
            visibility = "HIDDEN" if broken == "hidden" else "DEFAULT"
            entries.append((1, 0x1230, 36, "FUNC", binding, visibility, "10", "tgkill"))
        if broken == "truncated":
            declared = len(entries) + 1
        else:
            declared = len(entries)
        prefix = "File: libc-thread-signal.o\n" if archive else ""
        return prefix + f"Symbol table '{table}' contains {declared} entries:\n" + "".join(
            self._row(*entry) for entry in entries
        )

    def _inputs(self, directory: Path, *, candidate_broken: str | None = None,
                oracle_broken: str | None = None) -> list[Path]:
        paths: list[Path] = []
        for name, table, archive, candidate in (
            ("oracle-static", ".symtab", True, False),
            ("oracle-dynamic", ".dynsym", False, False),
            ("oracle-shared", ".symtab", False, False),
            ("candidate-static", ".symtab", True, True),
            ("candidate-dynamic", ".dynsym", False, True),
            ("candidate-shared", ".symtab", False, True),
        ):
            broken = candidate_broken if candidate else oracle_broken
            if not candidate and broken == "defined":
                body = self._table(table, archive=archive, candidate=True)
            else:
                body = self._table(table, archive=archive, candidate=candidate, broken=broken)
            path = directory / name
            path.write_text(body, encoding="utf-8")
            paths.append(path)
        return paths

    def test_x86_header_and_direct_provider_preserve_the_frozen_c_shape(self) -> None:
        self.assertTrue(PROVIDER.is_file(), "native x86 tgkill provider is missing")
        header = HEADER.read_text(encoding="utf-8")
        outer = "\n#else\n\n#ifdef __cplusplus\nextern \"C\" {\n"
        self.assertEqual(header.count(outer), 1)
        x86_branch, non_x86_branch = header.split(outer, 1)
        self.assertIn("#if defined(_BSD_SOURCE) || defined(_GNU_SOURCE)", x86_branch)
        self.assertIn("int tgkill(int, int, int);", x86_branch)
        self.assertIn("int tgkill(int, int, int);", non_x86_branch)

        static_root = STATIC_ROOT.read_text(encoding="utf-8")
        provider = PROVIDER.read_text(encoding="utf-8")
        raw_syscall = RAW_SYSCALL.read_text(encoding="utf-8")
        self.assertIn('#[path = "thread_signal.rs"]\nmod thread_signal;', static_root)
        for marker in (
            "3e100d45c5a0798c2d3862d5e2eef584c610ccf9",
            "SYS_TGKILL",
            "c_status",
            'pub extern "C" fn tgkill(',
            "caller-selected",
            "no caller-owned pointer arguments",
        ):
            self.assertIn(marker, provider)
        self.assertNotIn("SYS_GETPID", provider)
        self.assertNotIn("crabc_core", provider)
        self.assertIn("pub(crate) const SYS_TGKILL: i64 = 234;", raw_syscall)

    def test_complete_candidate_shape_and_explicit_musl_absence_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = symbols.validate(CONTRACT, *self._inputs(Path(temporary)))
        self.assertEqual(result["schema"], "crabc.x86_64-native-thread-signal-abi/v1")
        self.assertFalse(result["oracle"]["dynamic"]["public_tgkill_export"])
        self.assertEqual(result["candidate"]["shared_symtab"]["binding"], "GLOBAL")

    def test_weak_hidden_oracle_and_truncated_symbol_evidence_reject(self) -> None:
        for broken, expression in (
            ("weak", "FUNC GLOBAL DEFAULT"),
            ("hidden", "FUNC GLOBAL DEFAULT"),
            ("truncated", "truncated or malformed"),
        ):
            with self.subTest(broken=broken), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(symbols.NativeThreadSignalSymbolError, expression):
                    symbols.validate(CONTRACT, *self._inputs(Path(temporary), candidate_broken=broken))
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(symbols.NativeThreadSignalSymbolError, "absent public tgkill ABI"):
                symbols.validate(CONTRACT, *self._inputs(Path(temporary), oracle_broken="defined"))

    def test_numeric_non_promoting_contract_flag_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
            contract["public_support"] = 0
            altered = Path(temporary) / "contract.json"
            altered.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaisesRegex(symbols.NativeThreadSignalSymbolError, "non-promoting booleans"):
                symbols._load_contract(altered)

    def test_one_installed_header_object_is_reused_for_adapter_and_all_candidate_modes(self) -> None:
        for path in (PROBE, ADAPTER, CPP_GNU_PROBE, CPP_STRICT_PROBE, RUNNER, DOCUMENT):
            self.assertTrue(path.is_file(), f"missing native thread-signal input: {path}")
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)
        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)], cwd=ROOT, check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        probe = PROBE.read_text(encoding="utf-8")
        adapter = ADAPTER.read_text(encoding="utf-8")
        cpp_gnu_probe = CPP_GNU_PROBE.read_text(encoding="utf-8")
        cpp_strict_probe = CPP_STRICT_PROBE.read_text(encoding="utf-8")
        runner = RUNNER.read_text(encoding="utf-8")
        document = DOCUMENT.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")

        self.assertIn("#include <signal.h>", probe)
        self.assertIn("tgkill(child, child, 0)", probe)
        self.assertIn("tgkill(getpid(), getpid(), 0)", probe)
        self.assertIn("tgkill(child, INT_MAX, 0)", probe)
        self.assertIn("tgkill(child, child, 65)", probe)
        self.assertIn("tgkill(-1, child, 0)", probe)
        self.assertIn("tgkill(0, child, 0)", probe)
        self.assertIn("tgkill(child, -1, 0)", probe)
        self.assertIn("tgkill(child, 0, 0)", probe)
        self.assertIn("errno = ERANGE", probe)
        self.assertIn("sigprocmask(SIG_BLOCK", probe)
        self.assertIn("sigpending(&pending)", probe)
        self.assertIn("sigprocmask(SIG_UNBLOCK", probe)
        self.assertNotIn("100000", probe)
        self.assertIn("tgkill(child, child, SIGUSR1)", probe)
        self.assertNotIn("#include <sys/syscall.h>", probe)
        self.assertNotIn("syscall(SYS_tgkill", probe)
        self.assertIn("syscall(SYS_tgkill", adapter)
        self.assertIn("extern \"C\"", cpp_gnu_probe)
        self.assertIn("&tgkill", cpp_gnu_probe)
        self.assertIn("&tgkill", cpp_strict_probe)

        for marker in (
            '"$dynamic_product/bin/crabc-cc-dynamic" --dynamic-pie',
            '"$CC" --target=x86_64-linux-musl -std=c11 -nostdinc',
            "installed-header-preprocess",
            "installed-header-cxx17-gnu-preprocess",
            "installed-header-cxx17-gnu-compile",
            "installed-header-cxx17-strict",
            "-U_GNU_SOURCE",
            "-U_BSD_SOURCE",
            "-U_DEFAULT_SOURCE",
            "-U_ALL_SOURCE",
            "undeclared identifier 'tgkill'",
            '"$work/probe.o"',
            "oracle-adapter-compile",
            "candidate-static-pie-link",
            "for mode in pie non-pie; do",
            "for entry in kernel direct; do",
            "readelf --dyn-syms -W \"$dynamic_product/usr/lib/libc.so\"",
            "readelf -Ws \"$dynamic_product/usr/lib/libc.so\"",
            "native_thread_signal_abi_symbols.py",
            "local-default-static-delta",
            "expected-addition=tgkill",
            "unintegrated-additions",
            "SYS_TGKILL",
            "caller-selected-child:signal0:delivery:ESRCH:EINVAL",
        ):
            self.assertIn(marker, runner)
        self.assertIn("one installed-header object", document)
        self.assertIn("not a musl public `tgkill` ABI", document)
        self.assertIn("[native-thread-signal-abi.md](native-thread-signal-abi.md)", readme)


if __name__ == "__main__":
    unittest.main()
