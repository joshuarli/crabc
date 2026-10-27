#!/usr/bin/env python3
"""Native Linux/x86-64 proof for the bounded static-PIE CRT bootstrap."""

from __future__ import annotations

import json
import os
import platform
import re
import resource
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


CRT_ROOT = Path(__file__).resolve().parents[1]
ROOT = CRT_ROOT.parent
sys.path.insert(0, str(ROOT))
from scripts.rust_toolchain import pinned_toolchain
from scripts import native_build_tools
BUILDER = CRT_ROOT / "build_x86_64.py"
FIXTURE = CRT_ROOT / "fixtures" / "static_pie_fixture_x86_64.rs"
BUNDLE_FIXTURE = CRT_ROOT / "fixtures" / "static_pie_builtins_bundle_x86_64.rs"
BUILTINS_BUILDER = ROOT / "builtins" / "build_x86_64.py"
TARGET = "x86_64-unknown-linux-musl"
PINNED_TOOLCHAIN = pinned_toolchain(ROOT)

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
DT_PLTGOT = 3
DT_JMPREL = 23
R_X86_64_RELATIVE = 8
R_X86_64_64 = 1


def native_x86_64_evidence() -> bool:
    return (
        os.environ.get("CRABC_CRT_X86_64_EVIDENCE") == "native"
        and platform.system() == "Linux"
        and platform.machine() in {"x86_64", "amd64"}
    )


def disable_core_dump() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def toolchain_rustc() -> list[str]:
    compiler = Path("/opt/rustup/toolchains") / f"{PINNED_TOOLCHAIN}-{TARGET}/bin/rustc"
    return native_build_tools.compile_command(compiler)


def link_editor() -> str:
    return str(native_build_tools.MOLD)


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
    if DT_JMPREL in tags:
        raise AssertionError("static PIE unexpectedly retains dynamic PLT relocations")
    if DT_PLTGOT in tags:
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, header[6] + index * header[11])
                    for index in range(header[12])]
        strings = sections[header[13]]
        names = data[strings[4]:strings[4] + strings[5]]
        reserved = [section for section in sections if names[section[0]:].split(b"\0", 1)[0] == b".got.plt"]
        dynamic = next(program for program in program_headers if program[0] == PT_DYNAMIC)
        if len(reserved) != 1 or reserved[0][3] != tags[DT_PLTGOT] or reserved[0][5] != 24 \
                or reserved[0][2] & 4 or struct.unpack_from("<QQQ", data, reserved[0][4]) != (dynamic[3], 0, 0):
            raise AssertionError("static PIE GOT/PLT exceeds the three inert reserved entries")
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


def duplicate_relro_header(path: Path) -> Path:
    data, headers = elf_layout(path)
    relro = next(index for index, header in enumerate(headers) if header[0] == 0x6474e552)
    spare = next(index for index, header in enumerate(headers) if header[0] == 0x6474e551)
    mutable = bytearray(data)
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    source = program_offset + relro * 56
    target = program_offset + spare * 56
    mutable[target:target + 56] = data[source:source + 56]
    duplicate = path.with_name(path.name + ".duplicate-relro")
    duplicate.write_bytes(mutable)
    duplicate.chmod(0o755)
    return duplicate


def empty_relro_header(path: Path) -> Path:
    data, headers = elf_layout(path)
    relro = next(index for index, header in enumerate(headers) if header[0] == 0x6474e552)
    mutable = bytearray(data)
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    struct.pack_into("<Q", mutable, program_offset + relro * 56 + 40, 0)
    empty = path.with_name(path.name + ".empty-relro")
    empty.write_bytes(mutable)
    empty.chmod(0o755)
    return empty


def executable_relro_header(path: Path) -> Path:
    data, headers = elf_layout(path)
    relro = next(index for index, header in enumerate(headers) if header[0] == 0x6474e552)
    executable = next(header for header in headers if header[0] == PT_LOAD and header[1] & 1)
    mutable = bytearray(data)
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    struct.pack_into("<Q", mutable, program_offset + relro * 56 + 16, executable[3])
    struct.pack_into("<Q", mutable, program_offset + relro * 56 + 40, 1)
    bad = path.with_name(path.name + ".executable-relro")
    bad.write_bytes(mutable)
    bad.chmod(0o755)
    return bad


def overlapping_executable_load(path: Path) -> Path:
    data, headers = elf_layout(path)
    writable = next(index for index, header in enumerate(headers) if header[0] == PT_LOAD and header[1] & 2)
    spare = next(index for index, header in enumerate(headers) if header[0] == 0x6474e551)
    mutable = bytearray(data)
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    source = program_offset + writable * 56
    target = program_offset + spare * 56
    mutable[target:target + 56] = data[source:source + 56]
    struct.pack_into("<I", mutable, target + 4, 5)
    overlap = path.with_name(path.name + ".overlapping-executable-load")
    overlap.write_bytes(mutable)
    overlap.chmod(0o755)
    return overlap


def mutate_program_header(path: Path, kind: int, replacement: int, flags: int) -> Path:
    data, headers = elf_layout(path)
    index = next(index for index, header in enumerate(headers) if header[0] == kind)
    mutable = bytearray(data)
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    struct.pack_into("<II", mutable, program_offset + index * 56, replacement, flags)
    changed = path.with_name(path.name + f".header-{kind}-{replacement}-{flags}")
    changed.write_bytes(mutable)
    changed.chmod(0o755)
    return changed


def duplicate_stack_header(path: Path) -> Path:
    data, headers = elf_layout(path)
    source_index = next(index for index, header in enumerate(headers) if header[0] == 0x6474e551)
    target_index = next(index for index, header in enumerate(headers) if header[0] == 0x6474e552)
    mutable = bytearray(data)
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    source = program_offset + source_index * 56
    target = program_offset + target_index * 56
    mutable[target:target + 56] = data[source:source + 56]
    changed = path.with_name(path.name + ".duplicate-stack")
    changed.write_bytes(mutable)
    changed.chmod(0o755)
    return changed


def overlapping_executable_bss(path: Path) -> Path:
    data, headers = elf_layout(path)
    writable = [header for header in headers if header[0] == PT_LOAD and header[1] & 2][-1]
    target_index = next(index for index, header in enumerate(headers) if header[0] == 0x6474e550)
    address = (writable[3] + writable[6] - 1) & -4096
    mutable = bytearray(data)
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    struct.pack_into("<IIQQQQQQ", mutable, program_offset + target_index * 56,
                     PT_LOAD, 5, 0, address, address, 0, 4096, 4096)
    changed = path.with_name(path.name + ".executable-bss-overlap")
    changed.write_bytes(mutable)
    changed.chmod(0o755)
    return changed


def duplicate_relocation_tag(path: Path, tag: int) -> Path:
    data, headers = elf_layout(path)
    dynamic = next(header for header in headers if header[0] == PT_DYNAMIC)
    entries = range(dynamic[2], dynamic[2] + dynamic[5], 16)
    value = next(struct.unpack_from("<qQ", data, offset)[1] for offset in entries
                 if struct.unpack_from("<q", data, offset)[0] == tag)
    debug = next(offset for offset in entries if struct.unpack_from("<q", data, offset)[0] == 21)
    mutable = bytearray(data)
    struct.pack_into("<qQ", mutable, debug, tag, value)
    duplicate = path.with_name(path.name + f".duplicate-{tag}")
    duplicate.write_bytes(mutable)
    duplicate.chmod(0o755)
    return duplicate


def invalid_rela_entry_size(path: Path) -> Path:
    data, headers = elf_layout(path)
    dynamic = next(header for header in headers if header[0] == PT_DYNAMIC)
    entry = next(offset for offset in range(dynamic[2], dynamic[2] + dynamic[5], 16)
                 if struct.unpack_from("<q", data, offset)[0] == 9)
    mutable = bytearray(data)
    struct.pack_into("<Q", mutable, entry + 8, 8)
    invalid = path.with_name(path.name + ".invalid-relaent")
    invalid.write_bytes(mutable)
    invalid.chmod(0o755)
    return invalid


def missing_relocation_tag(path: Path, tag: int) -> Path:
    data, headers = elf_layout(path)
    dynamic = next(header for header in headers if header[0] == PT_DYNAMIC)
    entry = next(offset for offset in range(dynamic[2], dynamic[2] + dynamic[5], 16)
                 if struct.unpack_from("<q", data, offset)[0] == tag)
    mutable = bytearray(data)
    struct.pack_into("<qQ", mutable, entry, 21, 0)
    missing = path.with_name(path.name + f".missing-{tag}")
    missing.write_bytes(mutable)
    missing.chmod(0o755)
    return missing


def invalid_first_relr(path: Path, value: int) -> Path:
    data, headers = elf_layout(path)
    tags = dynamic_tags(data, headers)
    table = virtual_offset(headers, tags[DT_RELR])
    mutable = bytearray(data)
    struct.pack_into("<Q", mutable, table, value)
    invalid = path.with_name(path.name + f".invalid-relr-{value}")
    invalid.write_bytes(mutable)
    invalid.chmod(0o755)
    return invalid


def dynamic_declaration(path: Path, tag: int, value: int) -> Path:
    data, headers = elf_layout(path)
    dynamic = next(header for header in headers if header[0] == PT_DYNAMIC)
    entry = next(offset for offset in range(dynamic[2], dynamic[2] + dynamic[5], 16)
                 if struct.unpack_from("<q", data, offset)[0] == 21)
    mutable = bytearray(data)
    struct.pack_into("<qQ", mutable, entry, tag, value)
    invalid = path.with_name(path.name + f".dynamic-{tag}")
    invalid.write_bytes(mutable)
    invalid.chmod(0o755)
    return invalid


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


def compile_fixture(source: Path, output: Path) -> None:
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
            str(source),
            "-o",
            str(output),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if compile.returncode != 0:
        raise AssertionError(compile.stderr.decode(errors="replace"))


def closed_bundle_inputs(crt_output: Path, fixture: Path, builtins: Path, extras: tuple[Path, ...] = ()) -> list[str]:
    """Return the only permitted inputs for the private static-PIE bundle.

    The closed list is evidence infrastructure, not a compiler driver: adding
    a CRT object or helper archive is rejected before mold observes it, so an
    ambient `crt1`, libgcc, or compiler-rt cannot silently satisfy the proof.
    """

    if extras:
        raise ValueError("private static-PIE bundle rejects ambient CRT/runtime inputs")
    return [
        str(crt_output / "rcrt1.o"),
        str(crt_output / "crti.o"),
        str(fixture),
        str(crt_output / "crtn.o"),
        str(builtins),
    ]


@unittest.skipUnless(
    native_x86_64_evidence(),
    "requires the dedicated native Linux/x86-64 CRT evidence runner",
)
class X86_64StaticPieTests(unittest.TestCase):
    def test_hardened_static_pie_rejects_executable_or_missing_stack_and_wx_load(self) -> None:
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            crt_output = work / "crt"
            build = subprocess.run(
                [sys.executable, str(BUILDER), "--out-dir", str(crt_output), "--hardening-profile", "hardened",
                 "--llvm-objdump", str(Path("/opt/rustup/toolchains") / f"{PINNED_TOOLCHAIN}-{TARGET}/lib/rustlib/{TARGET}/bin/llvm-objdump")],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr.decode(errors="replace"))
            fixture = work / "fixture.o"
            compile = subprocess.run(
                toolchain_rustc() + ["--edition=2021", "--crate-type=lib", "--emit=obj", "--target", TARGET,
                                    "-C", "panic=abort", "-C", "opt-level=2", "-C", "relocation-model=pic",
                                    str(FIXTURE), "-o", str(fixture)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(compile.returncode, 0, compile.stderr.decode(errors="replace"))
            executable = work / "hardened-static-pie"
            link = subprocess.run(
                [link_editor(), "-pie", "-static", "--no-dynamic-linker", "-e", "_start", str(crt_output / "rcrt1.o"),
                 str(crt_output / "crti.o"), str(fixture), str(crt_output / "crtn.o"), "-o", str(executable)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(link.returncode, 0, link.stderr.decode(errors="replace"))
            normal = subprocess.run([str(executable)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(normal.returncode, 0, normal.stderr.decode(errors="replace"))
            for source, replacement, flags in ((0x6474e551, 0, 0), (0x6474e551, 0x6474e551, 7), (PT_LOAD, PT_LOAD, 7)):
                invalid = mutate_program_header(executable, source, replacement, flags)
                result = subprocess.run([str(invalid)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                                        preexec_fn=disable_core_dump)
                self.assertEqual(result.returncode, 127, result.stderr.decode(errors="replace"))
                self.assertEqual(result.stdout, b"")
            duplicate = subprocess.run([str(duplicate_stack_header(executable))], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, check=False, preexec_fn=disable_core_dump)
            self.assertEqual(duplicate.returncode, 127, duplicate.stderr.decode(errors="replace"))
            self.assertEqual(duplicate.stdout, b"")
            overlap = subprocess.run([str(overlapping_executable_bss(executable))], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, check=False, preexec_fn=disable_core_dump)
            self.assertEqual(overlap.returncode, 127, overlap.stderr.decode(errors="replace"))
            self.assertEqual(overlap.stdout, b"")
            compatible_crt = work / "compatible-crt"
            compatible_build = subprocess.run(
                [sys.executable, str(BUILDER), "--out-dir", str(compatible_crt), "--hardening-profile", "compatibility",
                 "--llvm-objdump", str(Path("/opt/rustup/toolchains") / f"{PINNED_TOOLCHAIN}-{TARGET}/lib/rustlib/{TARGET}/bin/llvm-objdump")],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(compatible_build.returncode, 0, compatible_build.stderr.decode(errors="replace"))
            compatible = work / "compatible-static-pie"
            compatible_link = subprocess.run(
                [link_editor(), "-pie", "-static", "--no-dynamic-linker", "-e", "_start", str(compatible_crt / "rcrt1.o"),
                 str(compatible_crt / "crti.o"), str(fixture), str(compatible_crt / "crtn.o"), "-o", str(compatible)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(compatible_link.returncode, 0, compatible_link.stderr.decode(errors="replace"))
            for source, replacement, flags in ((0x6474e551, 0, 0), (0x6474e551, 0x6474e551, 7), (PT_LOAD, PT_LOAD, 7)):
                valid = mutate_program_header(compatible, source, replacement, flags)
                result = subprocess.run([str(valid)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                                        preexec_fn=disable_core_dump)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                self.assertRegex(result.stdout, rb"^I[0-9a-f]{16}F$")
            compatible_overlap = subprocess.run([str(overlapping_executable_bss(compatible))], stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE, check=False, preexec_fn=disable_core_dump)
            self.assertNotEqual(compatible_overlap.returncode, 127)

    def test_static_pie_bootstrap_executes_and_rejects_unknown_relocations(self) -> None:
        if os.environ.get("CRABC_CRT_X86_64_EVIDENCE_SLICE") == "bundle":
            self.skipTest("bundle-only runner selects the CRT/builtins consumer")
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            crt_output = work / "crt"
            build = subprocess.run(
                [sys.executable, str(BUILDER), "--out-dir", str(crt_output), "--llvm-objdump",
                 str(Path("/opt/rustup/toolchains") / f"{PINNED_TOOLCHAIN}-{TARGET}/lib/rustlib/{TARGET}/bin/llvm-objdump")],
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
                ("relr", ("-z", "pack-relative-relocs",), True),
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

                relro_write = subprocess.run(
                    [str(executable), "!"], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, preexec_fn=disable_core_dump,
                )
                self.assertEqual(relro_write.returncode, -signal.SIGSEGV)
                self.assertEqual(relro_write.stdout, b"")

                duplicate = subprocess.run(
                    [str(duplicate_relro_header(executable))], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
                self.assertEqual(duplicate.returncode, 127, duplicate.stderr.decode(errors="replace"))
                self.assertEqual(duplicate.stdout, b"")

                empty = subprocess.run(
                    [str(empty_relro_header(executable))], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
                self.assertEqual(empty.returncode, 127, empty.stderr.decode(errors="replace"))
                self.assertEqual(empty.stdout, b"")

                executable_relro = subprocess.run(
                    [str(executable_relro_header(executable))], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, preexec_fn=disable_core_dump,
                )
                self.assertEqual(executable_relro.returncode, 127, executable_relro.stderr.decode(errors="replace"))
                self.assertEqual(executable_relro.stdout, b"")

                overlap = subprocess.run(
                    [str(overlapping_executable_load(executable))], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, preexec_fn=disable_core_dump,
                )
                self.assertEqual(overlap.returncode, 127, overlap.stderr.decode(errors="replace"))
                self.assertEqual(overlap.stdout, b"")

                for tag, value in ((1, 0), (2, 8), (17, 8), (18, 8), (19, 16), (20, 7), (22, 0), (23, 0), (30, 4)):
                    rejected = subprocess.run(
                        [str(dynamic_declaration(executable, tag, value))], stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                        preexec_fn=disable_core_dump,
                    )
                    self.assertEqual(rejected.returncode, 127, f"tag {tag}: {rejected.stderr.decode(errors='replace')}")
                    self.assertEqual(rejected.stdout, b"")

                tags = dynamic_tags(*elf_layout(executable))
                for tag in (7, 8, 9, 35, 36, 37):
                    if tag not in tags:
                        continue
                    duplicate_tag = subprocess.run(
                        [str(duplicate_relocation_tag(executable, tag))], stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                        preexec_fn=disable_core_dump,
                    )
                    self.assertEqual(duplicate_tag.returncode, 127, duplicate_tag.stderr.decode(errors="replace"))
                    self.assertEqual(duplicate_tag.stdout, b"")
                for tag in ((7, 8) if 7 in tags and 8 in tags else ()) + ((35, 36, 37) if 36 in tags else ()):
                    missing_tag = subprocess.run(
                        [str(missing_relocation_tag(executable, tag))], stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                        preexec_fn=disable_core_dump,
                    )
                    self.assertEqual(missing_tag.returncode, 127, missing_tag.stderr.decode(errors="replace"))
                    self.assertEqual(missing_tag.stdout, b"")
                if packed_relr:
                    for value in (1, 2, 0xfffffffffffffff8):
                        bad_relr = subprocess.run(
                            [str(invalid_first_relr(executable, value))], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                            preexec_fn=disable_core_dump,
                        )
                        self.assertEqual(bad_relr.returncode, 127, bad_relr.stderr.decode(errors="replace"))
                        self.assertEqual(bad_relr.stdout, b"")
                if not packed_relr:
                    bad_entry = subprocess.run(
                        [str(invalid_rela_entry_size(executable))], stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                        preexec_fn=disable_core_dump,
                    )
                    self.assertEqual(bad_entry.returncode, 127, bad_entry.stderr.decode(errors="replace"))
                    self.assertEqual(bad_entry.stdout, b"")
                    missing_entry = subprocess.run(
                        [str(missing_relocation_tag(executable, 9))], stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                        preexec_fn=disable_core_dump,
                    )
                    self.assertEqual(missing_entry.returncode, 127, missing_entry.stderr.decode(errors="replace"))
                    self.assertEqual(missing_entry.stdout, b"")
                    malformed = corrupt_first_relative_relocation(executable)
                    rejected = subprocess.run(
                        [str(malformed)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
                    )
                    self.assertEqual(rejected.returncode, 127, rejected.stderr.decode(errors="replace"))

    def test_static_pie_bundle_consumes_owned_crt_and_rust_builtins_only(self) -> None:
        if os.environ.get("CRABC_CRT_X86_64_EVIDENCE_SLICE") != "bundle":
            self.skipTest("static-pie runner selects the no-TLS CRT foundation")
        scratch = ROOT / ".work/tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            work = Path(temporary)
            crt_output = work / "crt"
            build = subprocess.run(
                [sys.executable, str(BUILDER), "--out-dir", str(crt_output), "--llvm-objdump",
                 str(Path("/opt/rustup/toolchains") / f"{PINNED_TOOLCHAIN}-{TARGET}/lib/rustlib/{TARGET}/bin/llvm-objdump")],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr.decode(errors="replace"))

            builtins = work / "libcrabc-builtins.a"
            builtins_build = subprocess.run(
                [sys.executable, str(BUILTINS_BUILDER), "--output", str(builtins), "--verify-reproducible"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(builtins_build.returncode, 0, builtins_build.stderr.decode(errors="replace"))
            provenance = json.loads(builtins.with_suffix(".a.provenance.json").read_text())
            self.assertEqual(provenance["target"], TARGET)
            self.assertTrue(provenance["reproducible"])
            self.assertIn("__udivti3", provenance["archive"]["defined_symbols"])
            self.assertEqual(provenance["archive"]["members"], ["crabc-builtins.o"])

            fixture = work / "static_pie_builtins_bundle_x86_64.o"
            compile_fixture(BUNDLE_FIXTURE, fixture)
            undefined = subprocess.run(
                [str(Path("/opt/rustup/toolchains") / f"{PINNED_TOOLCHAIN}-{TARGET}/lib/rustlib/{TARGET}/bin/llvm-nm"), "--undefined-only", "--extern-only", str(fixture)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(undefined.returncode, 0, undefined.stderr.decode(errors="replace"))
            self.assertIn("__udivti3", undefined.stdout.decode(errors="replace"))

            missing_builtins = work / "static-pie-bundle-missing-builtins"
            no_builtins_link = subprocess.run(
                [
                    link_editor(), "-pie", "-static", "--no-dynamic-linker", "-e", "_start",
                    str(crt_output / "rcrt1.o"), str(crt_output / "crti.o"), str(fixture),
                    str(crt_output / "crtn.o"), "-o", str(missing_builtins),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(no_builtins_link.returncode, 0, "bundle unexpectedly linked without owned builtins")
            self.assertIn("__udivti3", no_builtins_link.stderr.decode(errors="replace"))

            ambient_runtime = work / "ambient-libgcc.a"
            ambient_runtime.write_bytes(builtins.read_bytes())
            ambient_crt = work / "ambient-rcrt1.o"
            ambient_crt.write_bytes((crt_output / "rcrt1.o").read_bytes())
            with self.assertRaisesRegex(ValueError, "rejects ambient CRT/runtime inputs"):
                closed_bundle_inputs(crt_output, fixture, builtins, (ambient_runtime,))
            with self.assertRaisesRegex(ValueError, "rejects ambient CRT/runtime inputs"):
                closed_bundle_inputs(crt_output, fixture, builtins, (ambient_crt,))

            executable = work / "static-pie-rust-crt-builtins-bundle"
            link = subprocess.run(
                [
                    link_editor(), "-pie", "-static", "--no-dynamic-linker", "-e", "_start",
                    "--trace-symbol=__udivti3",
                    *closed_bundle_inputs(crt_output, fixture, builtins), "-o", str(executable),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(link.returncode, 0, link.stderr.decode(errors="replace"))
            trace = (link.stdout + link.stderr).decode(errors="replace")
            self.assertIn(str(builtins), trace)
            self.assertNotIn("libgcc", trace)
            self.assertNotIn("compiler-rt", trace)
            inspect_static_pie(executable, packed_relr=False)
            execution = subprocess.run(
                [str(executable)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
            )
            self.assertEqual(execution.returncode, 0, execution.stderr.decode(errors="replace"))
            self.assertEqual(execution.stdout, b"IBF")


if __name__ == "__main__":
    unittest.main()
