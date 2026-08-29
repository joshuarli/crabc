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
TLS_FIXTURE = CRT_ROOT / "fixtures" / "static_pie_tls_fixture_x86_64.S"
TARGET = "x86_64-unknown-linux-musl"
PINNED_TOOLCHAIN = "nightly-2026-07-24"

PT_DYNAMIC = 2
PT_INTERP = 3
PT_LOAD = 1
PT_TLS = 7
PF_R = 0x4
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


def assembler() -> str:
    candidate = shutil.which("as")
    if candidate is None:
        raise unittest.SkipTest("the native GNU assembler is unavailable")
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


def virtual_range_within_load(
    program_headers: list[tuple[int, int, int, int, int, int, int, int]],
    address: int,
    length: int,
    *,
    file_backed: bool,
    readable: bool,
) -> None:
    end = address + length
    if end < address:
        raise AssertionError("virtual range overflow")
    for program_type, flags, _, virtual_address, _, file_size, memory_size, _ in program_headers:
        if program_type != PT_LOAD or (readable and flags & PF_R == 0):
            continue
        limit = file_size if file_backed else memory_size
        if virtual_address <= address and end <= virtual_address + limit:
            return
    backing = "readable file-backed" if file_backed and readable else "mapped"
    raise AssertionError(f"0x{address:x}+0x{length:x} is not in a {backing} PT_LOAD range")


def inspect_static_pie(path: Path, *, packed_relr: bool, expect_tls: bool) -> None:
    data, program_headers = elf_layout(path)
    if any(header[0] == PT_INTERP for header in program_headers):
        raise AssertionError("static PIE unexpectedly has PT_INTERP")
    tls_headers = [header for header in program_headers if header[0] == PT_TLS]
    if expect_tls:
        if len(tls_headers) != 1:
            raise AssertionError("static TLS fixture must have exactly one PT_TLS image")
        _, _, _, tls_vaddr, _, tls_filesz, tls_memsz, tls_align = tls_headers[0]
        if (
            tls_filesz == 0
            or tls_memsz <= tls_filesz
            or tls_align < 4096
            or tls_align & (tls_align - 1) != 0
        ):
            raise AssertionError(
                "static PIE TLS fixture lost initialized/TBSS/high-alignment layout"
            )
        virtual_range_within_load(
            program_headers,
            tls_vaddr,
            tls_filesz,
            file_backed=True,
            readable=True,
        )
        virtual_range_within_load(
            program_headers,
            tls_vaddr,
            tls_memsz,
            file_backed=False,
            readable=False,
        )
    elif tls_headers:
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


def corrupt_tls_file_size(path: Path) -> Path:
    data, program_headers = elf_layout(path)
    tls_indexes = [index for index, header in enumerate(program_headers) if header[0] == PT_TLS]
    if len(tls_indexes) != 1:
        raise AssertionError("expected one PT_TLS image to corrupt")
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    program_size = struct.unpack_from("<H", data, 54)[0]
    tls_index = tls_indexes[0]
    tls_memsz = program_headers[tls_index][6]
    mutable = bytearray(data)
    struct.pack_into("<Q", mutable, program_offset + tls_index * program_size + 32, tls_memsz + 1)
    corrupted = path.with_name(path.name + ".bad-tls-filesz")
    corrupted.write_bytes(mutable)
    corrupted.chmod(0o755)
    return corrupted


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

            fixture_objects: dict[bool, Path] = {}
            for static_tls in (False, True):
                fixture_object = work / (
                    "static_pie_tls_rust_fixture_x86_64.o"
                    if static_tls
                    else "static_pie_no_tls_fixture_x86_64.o"
                )
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
                        *( ["--cfg", "crabc_static_pie_tls"] if static_tls else [] ),
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
                fixture_objects[static_tls] = fixture_object

            tls_fixture_object = work / "static_pie_tls_fixture_x86_64.o"
            tls_compile = subprocess.run(
                [assembler(), "--64", str(TLS_FIXTURE), "-o", str(tls_fixture_object)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(
                tls_compile.returncode,
                0,
                tls_compile.stderr.decode(errors="replace"),
            )

            relocation_variants = (
                ("rela", (), False),
                ("relr", ("--pack-dyn-relocs=relr",), True),
            )
            fixture_variants = (
                ("no-tls", False, (), rb"^I[0-9a-f]{16}F$"),
                ("static-tls", True, (tls_fixture_object,), rb"^PI[0-9a-f]{16}F$"),
            )
            for fixture_name, expect_tls, extra_objects, expected_output in fixture_variants:
                for name, relocation_arguments, packed_relr in relocation_variants:
                    executable = work / ("static-pie-" + fixture_name + "-" + name)
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
                            str(fixture_objects[expect_tls]),
                            *(str(object_file) for object_file in extra_objects),
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
                    inspect_static_pie(executable, packed_relr=packed_relr, expect_tls=expect_tls)

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
                    self.assertRegex(first.stdout, expected_output)
                    self.assertRegex(second.stdout, expected_output)
                    self.assertNotEqual(first.stdout, second.stdout, "static PIE did not receive distinct ASLR bases")

                    if not packed_relr:
                        malformed = corrupt_first_relative_relocation(executable)
                        rejected = subprocess.run(
                            [str(malformed)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
                        )
                        self.assertEqual(rejected.returncode, 127, rejected.stderr.decode(errors="replace"))
                        if expect_tls:
                            malformed_tls = corrupt_tls_file_size(executable)
                            rejected_tls = subprocess.run(
                                [str(malformed_tls)],
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                check=False,
                            )
                            self.assertEqual(
                                rejected_tls.returncode,
                                127,
                                rejected_tls.stderr.decode(errors="replace"),
                            )


if __name__ == "__main__":
    unittest.main()
