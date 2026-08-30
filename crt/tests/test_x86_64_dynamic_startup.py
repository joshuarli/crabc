#!/usr/bin/env python3
"""Native Linux/x86-64 proof for the private `Scrt1.o` entry bridge.

Pinned musl 1.2.6 is the dynamic-loader/libc launch oracle. A separate
freestanding fixture invokes the candidate's six-argument lifecycle callbacks
directly, because musl owns and invokes its own executable lifecycle. Neither
route builds candidate libc/ldso or makes a sysroot claim.
"""

from __future__ import annotations

import importlib.util
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
FIXTURE = CRT_ROOT / "fixtures" / "dynamic_startup_fixture_x86_64.c"
LIFECYCLE_FIXTURE = CRT_ROOT / "fixtures" / "dynamic_startup_lifecycle_fixture_x86_64.c"
TARGET = "x86_64-unknown-linux-musl"
MUSL_ROOT = Path("/opt/musl-1.2.6")
MUSL_LIB = MUSL_ROOT / "lib"
MUSL_SCRT1 = MUSL_LIB / "Scrt1.o"
MUSL_CRTI = MUSL_LIB / "crti.o"
MUSL_CRTN = MUSL_LIB / "crtn.o"
MUSL_LOADER = MUSL_LIB / "ld-musl-x86_64.so.1"
MUSL_SPECS = MUSL_LIB / "musl-gcc.specs"

ET_DYN = 3
ET_EXEC = 2
EM_X86_64 = 62
PT_INTERP = 3
PT_LOAD = 1
PT_NOTE = 4
PT_DYNAMIC = 2
SHT_NOTE = 7
SHF_ALLOC = 0x2
OWNED_CRT_NOTE = struct.pack("<III", 6, 4, 0x43525401) + b"CRABC\0\0\0" + struct.pack("<I", 1)


def native_x86_64_evidence() -> bool:
    return (
        os.environ.get("CRABC_X86_64_DYNAMIC_STARTUP_EVIDENCE") == "native"
        and platform.system() == "Linux"
        and platform.machine() in {"x86_64", "amd64"}
    )


def oracle_compiler() -> list[str]:
    wrapper = shutil.which("crabc-x86_64-musl-gcc")
    if wrapper is not None:
        return [wrapper]
    if MUSL_SPECS.is_file():
        compiler = shutil.which("gcc")
        if compiler is not None:
            return [compiler, "-specs", str(MUSL_SPECS)]
    raise unittest.SkipTest("pinned musl oracle compiler is unavailable")


def required_tool(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise unittest.SkipTest(f"{name} is unavailable")
    return resolved


def llvm_objdump() -> str:
    direct = shutil.which("llvm-objdump")
    if direct is not None:
        return direct
    rustup = shutil.which("rustup")
    if rustup is None:
        raise unittest.SkipTest("llvm-objdump is unavailable")
    sysroot = run([rustup, "run", "nightly-2026-07-24", "rustc", "--print", "sysroot"])
    if sysroot.returncode != 0:
        raise unittest.SkipTest(sysroot.stderr.decode(errors="replace"))
    candidate = (
        Path(sysroot.stdout.decode().strip())
        / "lib"
        / "rustlib"
        / TARGET
        / "bin"
        / "llvm-objdump"
    )
    if not candidate.is_file():
        raise unittest.SkipTest("pinned Rust llvm-objdump is unavailable")
    return str(candidate)


def run(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def build_fixture_object(work: Path) -> Path:
    object_path = work / "dynamic_startup_fixture_x86_64.o"
    compile_result = run(
        oracle_compiler()
        + [
            "-std=c11",
            "-fPIE",
            "-fno-stack-protector",
            "-ffreestanding",
            "-c",
            str(FIXTURE),
            "-o",
            str(object_path),
        ]
    )
    if compile_result.returncode != 0:
        raise AssertionError(compile_result.stderr.decode(errors="replace"))
    return object_path


def build_lifecycle_fixture_object(work: Path) -> Path:
    object_path = work / "dynamic_startup_lifecycle_fixture_x86_64.o"
    compile_result = run(
        oracle_compiler()
        + [
            "-std=c11",
            "-ffreestanding",
            "-fno-stack-protector",
            "-fno-pie",
            "-fno-asynchronous-unwind-tables",
            "-c",
            str(LIFECYCLE_FIXTURE),
            "-o",
            str(object_path),
        ]
    )
    if compile_result.returncode != 0:
        raise AssertionError(compile_result.stderr.decode(errors="replace"))
    return object_path


def link_dynamic_pie(
    output: Path,
    *,
    scrt1: Path,
    crti: Path,
    fixture: Path,
    crtn: Path,
) -> None:
    linked = run(
        oracle_compiler()
        + [
            "-nostdlib",
            "-nostartfiles",
            "-pie",
            "-Wl,-e,_start",
            f"-Wl,--dynamic-linker,{MUSL_LOADER}",
            f"-Wl,-rpath,{MUSL_LIB}",
            str(scrt1),
            str(crti),
            str(fixture),
            str(crtn),
            "-L",
            str(MUSL_LIB),
            "-lc",
            "-o",
            str(output),
        ]
    )
    if linked.returncode != 0:
        raise AssertionError(linked.stderr.decode(errors="replace"))


def link_freestanding_lifecycle_probe(output: Path, *, scrt1: Path, fixture: Path) -> None:
    linked = run(
        oracle_compiler()
        + [
            "-nostdlib",
            "-nostartfiles",
            "-static",
            "-no-pie",
            "-Wl,-e,_start",
            "-Wl,--build-id=none",
            str(scrt1),
            str(fixture),
            "-o",
            str(output),
        ]
    )
    if linked.returncode != 0:
        raise AssertionError(linked.stderr.decode(errors="replace"))


def elf_layout(
    path: Path,
    *,
    expected_type: int,
    description: str,
) -> tuple[bytes, list[tuple[int, int, int, int, int, int, int, int]], tuple[int, int, int]]:
    data = path.read_bytes()
    if len(data) < 64:
        raise AssertionError(f"{description} is too short for ELF64")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    (
        ident,
        elf_type,
        machine,
        _,
        _,
        program_offset,
        section_offset,
        _,
        header_size,
        program_size,
        program_count,
        section_size,
        section_count,
        section_name_index,
    ) = header
    if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
        raise AssertionError("expected little-endian ELF64")
    if elf_type != expected_type or machine != EM_X86_64:
        raise AssertionError(
            f"expected x86-64 {description}, got type={elf_type} machine={machine}"
        )
    if header_size != 64 or program_size != 56:
        raise AssertionError("malformed ELF64 program-header table")
    if section_size != 64 or section_count == 0 or section_name_index >= section_count:
        raise AssertionError("malformed ELF64 section-header table")
    return (
        data,
        [
            struct.unpack_from("<IIQQQQQQ", data, program_offset + index * program_size)
            for index in range(program_count)
        ],
        (section_offset, section_count, section_name_index),
    )


def assert_retained_owned_crt_note(
    data: bytes,
    program_headers: list[tuple[int, int, int, int, int, int, int, int]],
    section_table: tuple[int, int, int],
) -> None:
    section_offset, section_count, section_name_index = section_table
    raw_sections = [
        struct.unpack_from("<IIQQQQIIQQ", data, section_offset + index * 64)
        for index in range(section_count)
    ]
    name_section = raw_sections[section_name_index]
    name_offset, _, _, _, name_data_offset, name_data_size, *_ = name_section
    del name_offset
    names = data[name_data_offset : name_data_offset + name_data_size]

    def section_name(offset: int) -> str:
        end = names.find(b"\0", offset)
        if offset >= len(names) or end < 0:
            raise AssertionError("malformed section-name table")
        return names[offset:end].decode(errors="replace")

    matches = [
        section
        for section in raw_sections
        if section_name(section[0]) == ".note.crabc.owned-crt"
    ]
    if len(matches) != 1:
        raise AssertionError("linked dynamic PIE must retain exactly one owned-CRT note section")
    _, section_type, flags, _, offset, size, *_ = matches[0]
    if section_type != SHT_NOTE or flags & SHF_ALLOC == 0:
        raise AssertionError("linked owned-CRT note must be an allocated SHT_NOTE section")
    if data[offset : offset + size] != OWNED_CRT_NOTE:
        raise AssertionError("linked owned-CRT note has an unexpected wire value")
    if not any(
        header[0] == PT_NOTE and header[2] <= offset and offset + size <= header[2] + header[5]
        for header in program_headers
    ):
        raise AssertionError("linked owned-CRT note is not covered by a PT_NOTE segment")


def assert_dynamic_pie_contract(path: Path, *, require_owned_crt_note: bool) -> None:
    data, headers, section_table = elf_layout(path, expected_type=ET_DYN, description="ET_DYN dynamic PIE")
    interpreters = [header for header in headers if header[0] == PT_INTERP]
    if len(interpreters) != 1:
        raise AssertionError("dynamic PIE must carry exactly one PT_INTERP")
    _, _, offset, _, _, size, _, _ = interpreters[0]
    interpreter = data[offset : offset + size].rstrip(b"\0").decode()
    if interpreter != str(MUSL_LOADER):
        raise AssertionError(f"dynamic PIE interpreter {interpreter!r} is not pinned musl")
    if not any(header[0] == PT_LOAD for header in headers):
        raise AssertionError("dynamic PIE has no PT_LOAD")

    dynamic = run([required_tool("readelf"), "--dynamic", "--wide", str(path)])
    if dynamic.returncode != 0:
        raise AssertionError(dynamic.stderr.decode(errors="replace"))
    dynamic_text = dynamic.stdout.decode(errors="replace")
    needed = re.findall(r"Shared library: \[(.*?)\]", dynamic_text)
    if needed != ["libc.so"]:
        raise AssertionError(f"dynamic PIE has unexpected DT_NEEDED entries: {needed!r}")

    symbols = run([required_tool("readelf"), "--dyn-syms", "--wide", str(path)])
    if symbols.returncode != 0:
        raise AssertionError(symbols.stderr.decode(errors="replace"))
    symbol_text = symbols.stdout.decode(errors="replace")
    forbidden = ("GLIBC_", "libgcc", "__stack_chk_fail")
    if any(token in symbol_text for token in forbidden):
        raise AssertionError("dynamic PIE imports an ambient runtime boundary")
    if require_owned_crt_note:
        assert_retained_owned_crt_note(data, headers, section_table)


def assert_freestanding_lifecycle_contract(path: Path) -> None:
    _, headers, _ = elf_layout(path, expected_type=ET_EXEC, description="ET_EXEC lifecycle probe")
    if any(header[0] == PT_INTERP for header in headers):
        raise AssertionError("freestanding lifecycle probe must not carry PT_INTERP")
    if any(header[0] == PT_DYNAMIC for header in headers):
        raise AssertionError("freestanding lifecycle probe must not carry PT_DYNAMIC")
    if not any(header[0] == PT_LOAD for header in headers):
        raise AssertionError("freestanding lifecycle probe has no PT_LOAD")


def load_builder_module():
    specification = importlib.util.spec_from_file_location("crabc_x86_64_crt_builder", BUILDER)
    if specification is None or specification.loader is None:
        raise AssertionError("unable to load x86 CRT builder")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


@unittest.skipUnless(
    native_x86_64_evidence(),
    "requires the dedicated native Linux/x86-64 dynamic CRT evidence runner",
)
class X86_64DynamicStartupTests(unittest.TestCase):
    def test_scrt1_launches_under_musl_and_proves_private_lifecycle_bridge(self) -> None:
        for required in (MUSL_SCRT1, MUSL_CRTI, MUSL_CRTN, MUSL_LOADER, MUSL_SPECS):
            self.assertTrue(required.is_file(), f"missing pinned musl input: {required}")

        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            fixture = build_fixture_object(work)

            oracle = work / "musl-dynamic-startup"
            link_dynamic_pie(
                oracle,
                scrt1=MUSL_SCRT1,
                crti=MUSL_CRTI,
                fixture=fixture,
                crtn=MUSL_CRTN,
            )
            assert_dynamic_pie_contract(oracle, require_owned_crt_note=False)
            oracle_run = run([str(oracle)])
            self.assertEqual(oracle_run.returncode, 0, oracle_run.stderr.decode(errors="replace"))
            self.assertEqual(oracle_run.stdout, b"IMF")

            output = work / "candidate-crt"
            built = run(
                [
                    sys.executable,
                    str(BUILDER),
                    "--out-dir",
                    str(output),
                    "--llvm-objdump",
                    llvm_objdump(),
                ]
            )
            self.assertEqual(built.returncode, 0, built.stderr.decode(errors="replace"))

            candidate = work / "candidate-dynamic-startup"
            link_dynamic_pie(
                candidate,
                scrt1=output / "Scrt1.o",
                crti=output / "crti.o",
                fixture=fixture,
                crtn=output / "crtn.o",
            )
            assert_dynamic_pie_contract(candidate, require_owned_crt_note=True)
            candidate_run = run([str(candidate)])
            self.assertEqual(candidate_run.returncode, 0, candidate_run.stderr.decode(errors="replace"))
            self.assertEqual(candidate_run.stdout, oracle_run.stdout)

            report = __import__("json").loads(built.stdout)
            contract = report["objects"]["Scrt1.o"]["entry_machine_contract"]
            self.assertEqual(contract["loader_finalizer"], "null-musl-x86_64-convention")
            self.assertTrue(contract["no_early_got_or_tls_relocation"])
            self.assertEqual(contract["direct_handoff_symbol"], "__crabc_x86_64_dynamic_start")

            lifecycle_fixture = build_lifecycle_fixture_object(work)
            lifecycle_probe = work / "candidate-lifecycle-bridge"
            link_freestanding_lifecycle_probe(
                lifecycle_probe,
                scrt1=output / "Scrt1.o",
                fixture=lifecycle_fixture,
            )
            assert_freestanding_lifecycle_contract(lifecycle_probe)
            lifecycle_run = run([str(lifecycle_probe)])
            self.assertEqual(lifecycle_run.returncode, 0, lifecycle_run.stderr.decode(errors="replace"))
            self.assertEqual(lifecycle_run.stdout, b"PQIJKMYXF")

            builder = load_builder_module()
            forged = work / "forged-Scrt1.o"
            bytes_ = bytearray((output / "Scrt1.o").read_bytes())
            marker = b"CRABC\0\0\0\x01\0\0\0"
            marker_offset = bytes_.find(marker)
            self.assertGreaterEqual(marker_offset, 0, "candidate Scrt1.o lacks its owned CRT marker")
            bytes_[marker_offset + len(marker) - 1] ^= 1
            forged.write_bytes(bytes_)
            spec = next(item for item in builder.OBJECTS if item.name == "Scrt1.o")
            with self.assertRaisesRegex(builder.BuildError, "owned-CRT ELF note"):
                builder.inspect_object(spec, forged)


if __name__ == "__main__":
    unittest.main()
