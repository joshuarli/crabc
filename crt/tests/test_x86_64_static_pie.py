#!/usr/bin/env python3
"""Native Linux/x86-64 proof for the bounded static-PIE CRT bootstrap."""

from __future__ import annotations

import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


CRT_ROOT = Path(__file__).resolve().parents[1]
ROOT = CRT_ROOT.parent
BUILDER = CRT_ROOT / "build_x86_64.py"
FIXTURE = CRT_ROOT / "fixtures" / "static_pie_fixture_x86_64.rs"
TARGET = "x86_64-unknown-linux-musl"
PINNED_TOOLCHAIN = "nightly-2026-07-24"

PT_DYNAMIC = 2
PT_INTERP = 3
PT_LOAD = 1
PT_TLS = 7
ET_DYN = 3
EM_X86_64 = 62
DT_NULL = 0
DT_NEEDED = 1
DT_RELA = 7
DT_RELASZ = 8
DT_RELR = 36
R_X86_64_RELATIVE = 8
R_X86_64_64 = 1


def native_x86_64_evidence() -> bool:
    return (
        os.environ.get("CRABC_CRT_X86_64_EVIDENCE") == "native"
        and platform.system() == "Linux"
        and platform.machine() in {"x86_64", "amd64"}
    )


def toolchain_rustc() -> list[str]:
    rustup = shutil.which("rustup")
    if rustup is None:
        raise unittest.SkipTest("rustup is unavailable")
    return [rustup, "run", PINNED_TOOLCHAIN, "rustc"]


def link_editor() -> str:
    candidate = shutil.which("ld.lld")
    if candidate is None:
        raise unittest.SkipTest("ld.lld is unavailable")
    return candidate


def elf_layout(path: Path) -> tuple[bytes, list[tuple[int, int, int, int, int, int, int, int]]]:
    data = path.read_bytes()
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    ident, elf_type, machine, _, _, program_offset, _, _, header_size, program_size, program_count, *_ = header
    if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
        raise AssertionError("expected little-endian ELF64")
    if elf_type != ET_DYN or machine != EM_X86_64:
        raise AssertionError(f"expected x86-64 ET_DYN static PIE, got type={elf_type} machine={machine}")
    if header_size != 64 or program_size != 56:
        raise AssertionError("malformed ELF64 program-header table")
    program_headers = [
        struct.unpack_from("<IIQQQQQQ", data, program_offset + index * program_size)
        for index in range(program_count)
    ]
    return data, program_headers


def dynamic_tags(data: bytes, program_headers: list[tuple[int, int, int, int, int, int, int, int]]) -> dict[int, int]:
    dynamic_headers = [header for header in program_headers if header[0] == PT_DYNAMIC]
    if len(dynamic_headers) != 1:
        raise AssertionError("static PIE must have exactly one PT_DYNAMIC")
    _, _, file_offset, _, _, file_size, _, _ = dynamic_headers[0]
    tags: dict[int, int] = {}
    for offset in range(file_offset, file_offset + file_size, 16):
        tag, value = struct.unpack_from("<qQ", data, offset)
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED:
            raise AssertionError("static PIE unexpectedly has DT_NEEDED")
        tags[tag] = value
    return tags


def virtual_offset(program_headers: list[tuple[int, int, int, int, int, int, int, int]], address: int) -> int:
    for program_type, _, file_offset, virtual_address, _, file_size, memory_size, _ in program_headers:
        if program_type != PT_LOAD:
            continue
        if virtual_address <= address < virtual_address + memory_size:
            relative = address - virtual_address
            if relative >= file_size:
                break
            return file_offset + relative
    raise AssertionError(f"virtual address 0x{address:x} is not file-backed by PT_LOAD")


def inspect_static_pie(path: Path, *, packed_relr: bool) -> None:
    data, program_headers = elf_layout(path)
    if any(header[0] == PT_INTERP for header in program_headers):
        raise AssertionError("static PIE unexpectedly has PT_INTERP")
    tls_headers = [header for header in program_headers if header[0] == PT_TLS]
    if tls_headers:
        raise AssertionError("no-TLS static PIE fixture unexpectedly has PT_TLS")
    tags = dynamic_tags(data, program_headers)
    if packed_relr:
        if DT_RELR not in tags:
            raise AssertionError("packed static PIE lacks DT_RELR")
    elif DT_RELA not in tags:
        raise AssertionError("static PIE lacks DT_RELA")
    if any(info & 0xFFFFFFFF != R_X86_64_RELATIVE for _, info, _ in relocation_summary(path)):
        raise AssertionError("static PIE unexpectedly retains a non-relative dynamic relocation")


def corrupt_first_relative_relocation(path: Path) -> Path:
    data, program_headers = elf_layout(path)
    tags = dynamic_tags(data, program_headers)
    rela = tags.get(DT_RELA)
    rela_size = tags.get(DT_RELASZ)
    if rela is None or rela_size is None or rela_size % 24 != 0:
        raise AssertionError("RELA static PIE lacks a well-formed DT_RELA table")
    table = virtual_offset(program_headers, rela)
    mutable = bytearray(data)
    for offset in range(table, table + rela_size, 24):
        info = struct.unpack_from("<Q", mutable, offset + 8)[0]
        if info & 0xFFFFFFFF == R_X86_64_RELATIVE:
            struct.pack_into("<Q", mutable, offset + 8, (info & ~0xFFFFFFFF) | R_X86_64_64)
            corrupted = path.with_name(path.name + ".bad-rela")
            corrupted.write_bytes(mutable)
            corrupted.chmod(0o755)
            return corrupted
    raise AssertionError("RELA static PIE has no R_X86_64_RELATIVE entry to corrupt")


def relocation_summary(path: Path) -> list[tuple[int, int, int]]:
    data, program_headers = elf_layout(path)
    tags = dynamic_tags(data, program_headers)
    rela = tags.get(DT_RELA)
    rela_size = tags.get(DT_RELASZ)
    if rela is None or rela_size is None:
        return []
    table = virtual_offset(program_headers, rela)
    return [
        struct.unpack_from("<QQq", data, offset)
        for offset in range(table, table + rela_size, 24)
    ]


def relr_summary(path: Path) -> list[int]:
    data, program_headers = elf_layout(path)
    tags = dynamic_tags(data, program_headers)
    relr = tags.get(DT_RELR)
    relr_size = tags.get(35)
    if relr is None or relr_size is None or relr_size % 8 != 0:
        return []
    table = virtual_offset(program_headers, relr)
    return [struct.unpack_from("<Q", data, offset)[0] for offset in range(table, table + relr_size, 8)]


@unittest.skipUnless(
    native_x86_64_evidence(),
    "requires the dedicated native Linux/x86-64 CRT evidence runner",
)
class X86_64StaticPieTests(unittest.TestCase):
    def test_static_pie_bootstrap_executes_and_rejects_unknown_relocations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            crt_output = work / "crt"
            build = subprocess.run(
                [sys.executable, str(BUILDER), "--out-dir", str(crt_output)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr.decode(errors="replace"))

            fixture_object = work / "static_pie_fixture_x86_64.o"
            compile = subprocess.run(
                toolchain_rustc()
                + [
                    "--edition=2021",
                    "--crate-type=lib",
                    "--emit=obj",
                    "--target",
                    TARGET,
                    "-C",
                    "panic=abort",
                    "-C",
                    "opt-level=2",
                    "-C",
                    "relocation-model=pic",
                    "--remap-path-prefix",
                    f"{ROOT}=/crabc",
                    str(FIXTURE),
                    "-o",
                    str(fixture_object),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(compile.returncode, 0, compile.stderr.decode(errors="replace"))

            relocation_variants = (
                ("rela", (), False),
                ("relr", ("--pack-dyn-relocs=relr",), True),
            )
            for name, relocation_arguments, packed_relr in relocation_variants:
                executable = work / ("static-pie-no-tls-" + name)
                link = subprocess.run(
                    [
                        link_editor(),
                        "-pie",
                        "-static",
                        "--no-dynamic-linker",
                        "-e",
                        "_start",
                        *relocation_arguments,
                        str(crt_output / "rcrt1.o"),
                        str(crt_output / "crti.o"),
                        str(fixture_object),
                        str(crt_output / "crtn.o"),
                        "-o",
                        str(executable),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(link.returncode, 0, link.stderr.decode(errors="replace"))
                inspect_static_pie(executable, packed_relr=packed_relr)

                first = subprocess.run(
                    [str(executable)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
                )
                second = subprocess.run(
                    [str(executable)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
                )
                self.assertEqual(
                    first.returncode,
                    0,
                    f"stdout={first.stdout!r} stderr={first.stderr.decode(errors='replace')} "
                    f"tags={dynamic_tags(*elf_layout(executable))!r} "
                    f"relocations={relocation_summary(executable)!r} relr={relr_summary(executable)!r}",
                )
                self.assertEqual(
                    second.returncode,
                    0,
                    f"stdout={second.stdout!r} stderr={second.stderr.decode(errors='replace')}",
                )
                self.assertRegex(first.stdout, rb"^I[0-9a-f]{16}F$")
                self.assertRegex(second.stdout, rb"^I[0-9a-f]{16}F$")
                self.assertNotEqual(first.stdout, second.stdout, "static PIE did not receive distinct ASLR bases")

                if not packed_relr:
                    malformed = corrupt_first_relative_relocation(executable)
                    rejected = subprocess.run(
                        [str(malformed)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
                    )
                    self.assertEqual(rejected.returncode, 127, rejected.stderr.decode(errors="replace"))


if __name__ == "__main__":
    unittest.main()
