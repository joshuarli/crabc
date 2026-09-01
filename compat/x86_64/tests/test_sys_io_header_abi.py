#!/usr/bin/env python3
"""Focused contract for the x86 ``<sys/io.h>`` inline port-I/O boundary."""

from __future__ import annotations

import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PUBLIC_HEADER = ROOT / "include" / "sys" / "io.h"
INLINE_HEADER = ROOT / "include" / "bits" / "io.h"
RUNNER = ROOT / "compat" / "x86_64" / "run_sys_io_header_abi.sh"
C_PROBE = ROOT / "compat" / "x86_64" / "sys_io_header_abi_probe.c"
CXX_PROBE = ROOT / "compat" / "x86_64" / "sys_io_header_abi_probe.cpp"
DISPATCHER = ROOT / "scripts" / "dev-x86_64.sh"
INLINE_NAMES = (
    "inb",
    "inw",
    "inl",
    "outb",
    "outw",
    "outl",
    "insb",
    "insw",
    "insl",
    "outsb",
    "outsw",
    "outsl",
)


class SysIoHeaderAbiTests(unittest.TestCase):
    def test_x86_public_entry_point_retains_musl_inline_contract(self) -> None:
        public_header = PUBLIC_HEADER.read_text(encoding="utf-8")
        self.assertIn('#ifdef __cplusplus\nextern "C" {\n#endif', public_header)
        self.assertIn("#include <features.h>", public_header)
        self.assertIn("#if defined(__x86_64__)\n#include <bits/io.h>\n#endif", public_header)
        self.assertIn("int iopl(int);", public_header)
        self.assertIn("int ioperm(unsigned long, unsigned long, int);", public_header)

        inline_header = INLINE_HEADER.read_text(encoding="utf-8")
        self.assertIn("arch/x86_64/bits/io.h", inline_header)
        self.assertIn("#if defined(__x86_64__)", inline_header)
        for name in INLINE_NAMES:
            self.assertIn(f" {name}(", inline_header)
        for phrase in (
            '"dN" (__port)',
            '"+S" (__buf)',
            '"+D" (__buf)',
            '"cld; rep; outsb"',
            '"cld; rep; outsw"',
            '"cld; rep; outsl"',
            '"cld; rep; insb"',
            '"cld; rep; insw"',
            '"cld; rep; insl"',
        ):
            self.assertIn(phrase, inline_header)
        self.assertNotIn('"memory"', inline_header)

    def test_probes_and_runner_keep_execution_outside_the_header_gate(self) -> None:
        for probe in (C_PROBE.read_text(encoding="utf-8"), CXX_PROBE.read_text(encoding="utf-8")):
            self.assertIn("#include <sys/io.h>", probe)
            self.assertIn("iopl_signature", probe)
            self.assertIn("ioperm_signature", probe)
            for signature in (
                "outb_signature",
                "outw_signature",
                "outl_signature",
                "inb_signature",
                "inw_signature",
                "inl_signature",
                "outs_signature",
                "ins_signature",
            ):
                self.assertIn(signature, probe)
            for name in INLINE_NAMES:
                self.assertIn(f"{name}(", probe)
            self.assertNotIn("main(", probe)

        syntax = subprocess.run(
            ["bash", "-n", str(RUNNER)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode), 0o755)

        runner = RUNNER.read_text(encoding="utf-8")
        for phrase in (
            "readonly EXPECTED_PROFILE_COUNT=7",
            "c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict",
            "-nostdinc",
            "-nostdinc++",
            "candidate trace reached pinned musl despite -nostdinc",
            "trace escaped its declared header roots",
            "trace omitted $root/$header",
            "nm --undefined-only",
            "inline ${inline_name} an external reference",
            "objdump -d --disassemble",
            "rep.*${mnemonic}",
            "no port-I/O execution",
        ):
            self.assertIn(phrase, runner)

    def test_dispatcher_exposes_only_the_compile_object_gate(self) -> None:
        dispatcher = DISPATCHER.read_text(encoding="utf-8")
        for phrase in (
            "sys-io-header-abi)",
            "run_sys_io_header_abi()",
            "run_sys_io_header_abi.sh",
            "sys-io-header-abi takes no arguments",
        ):
            self.assertIn(phrase, dispatcher)
        self.assertNotIn("libc-sys-io", dispatcher)


if __name__ == "__main__":
    unittest.main()
