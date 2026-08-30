#!/usr/bin/env python3
"""Closed native x86-64 dynamic-PIE CRT link-contract evidence.

This deliberately proves only the handoff from the Rust-produced
``Scrt1.o``/``crti.o``/``crtn.o`` objects into the pinned musl dynamic route.
It is a link provenance and ELF-boundary audit, not an x86 crabc loader,
libc, installed sysroot, or general dynamic-CRT claim.
"""

from __future__ import annotations

import importlib.util
import json
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
TARGET = "x86_64-unknown-linux-musl"
MUSL_ROOT = Path("/opt/musl-1.2.6")
MUSL_LIB = MUSL_ROOT / "lib"
MUSL_LOADER = MUSL_LIB / "ld-musl-x86_64.so.1"
MUSL_SCRT1 = MUSL_LIB / "Scrt1.o"
MUSL_SPECS = MUSL_LIB / "musl-gcc.specs"

ET_DYN = 3
EM_X86_64 = 62
PT_DYNAMIC = 2
PT_INTERP = 3


def native_x86_64_evidence() -> bool:
    return (
        os.environ.get("CRABC_X86_64_DYNAMIC_LINK_CONTRACT_EVIDENCE") == "native"
        and platform.system() == "Linux"
        and platform.machine() in {"x86_64", "amd64"}
    )


def run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def required_tool(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise unittest.SkipTest(f"{name} is unavailable")
    return resolved


def oracle_compiler() -> list[str]:
    wrapper = shutil.which("crabc-x86_64-musl-gcc")
    if wrapper is not None:
        return [wrapper]
    compiler = shutil.which("gcc")
    if compiler is not None and MUSL_SPECS.is_file():
        return [compiler, "-specs", str(MUSL_SPECS)]
    raise unittest.SkipTest("pinned musl oracle compiler is unavailable")


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


def build_fixture_object(work: Path) -> Path:
    fixture = work / "dynamic-link-contract-fixture.o"
    built = run(
        oracle_compiler()
        + [
            "-std=c11",
            "-ffreestanding",
            "-fno-stack-protector",
            "-fPIE",
            "-fno-asynchronous-unwind-tables",
            "-c",
            str(FIXTURE),
            "-o",
            str(fixture),
        ]
    )
    if built.returncode != 0:
        raise AssertionError(built.stderr.decode(errors="replace"))
    return fixture


def build_candidate_crt(work: Path) -> Path:
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
    if built.returncode != 0:
        raise AssertionError(built.stderr.decode(errors="replace"))
    report = json.loads(built.stdout)
    contract = report["objects"]["Scrt1.o"]["entry_machine_contract"]
    if contract["loader_finalizer"] != "null-musl-x86_64-convention":
        raise AssertionError("candidate Scrt1.o drifted from musl's null finalizer convention")
    if contract["direct_handoff_symbol"] != "__crabc_x86_64_dynamic_start":
        raise AssertionError("candidate Scrt1.o no longer has the direct Rust startup helper")
    return output


def link_controlled_dynamic_pie(output: Path, *, crt: Path, fixture: Path, link_map: Path) -> None:
    linked = run(
        oracle_compiler()
        + [
            "-nostdlib",
            "-nostartfiles",
            "-pie",
            "-Wl,-e,_start",
            "-Wl,-z,defs",
            f"-Wl,--dynamic-linker,{MUSL_LOADER}",
            f"-Wl,-rpath,{MUSL_LIB}",
            f"-Wl,-Map,{link_map}",
            str(crt / "Scrt1.o"),
            str(crt / "crti.o"),
            str(fixture),
            str(crt / "crtn.o"),
            "-L",
            str(MUSL_LIB),
            "-lc",
            "-o",
            str(output),
        ]
    )
    if linked.returncode != 0:
        raise AssertionError(linked.stderr.decode(errors="replace"))


def elf_layout(path: Path) -> tuple[bytes, tuple[int, int], list[tuple[int, int, int, int, int, int, int, int]]]:
    data = path.read_bytes()
    if len(data) < 64:
        raise AssertionError("dynamic PIE is too short for ELF64")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    ident, elf_type, machine, _, entry, program_offset, _, _, header_size, program_size, program_count, *_ = header
    if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
        raise AssertionError("dynamic PIE must be little-endian ELF64")
    if elf_type != ET_DYN or machine != EM_X86_64:
        raise AssertionError(f"expected ET_DYN x86-64, got type={elf_type} machine={machine}")
    if header_size != 64 or program_size != 56:
        raise AssertionError("malformed ELF64 program header table")
    headers = [
        struct.unpack_from("<IIQQQQQQ", data, program_offset + index * program_size)
        for index in range(program_count)
    ]
    return data, (entry, program_count), headers


def symbol_table(path: Path) -> dict[str, tuple[int, str, str, str]]:
    result = run([required_tool("readelf"), "--symbols", "--wide", str(path)])
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode(errors="replace"))
    symbols: dict[str, tuple[int, str, str, str]] = {}
    pattern = re.compile(
        r"^\s*\d+:\s*([0-9a-fA-F]+)\s+\d+\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)\s+(.+?)\s*$"
    )
    for line in result.stdout.decode(errors="replace").splitlines():
        match = pattern.match(line)
        if match is None:
            continue
        value, symbol_type, bind, section, name = match.groups()
        name = name.split("@", 1)[0]
        if name and name not in symbols:
            symbols[name] = (int(value, 16), symbol_type, bind, section)
    return symbols


def dynamic_text(path: Path) -> str:
    result = run([required_tool("readelf"), "--dynamic", "--wide", str(path)])
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode(errors="replace"))
    return result.stdout.decode(errors="replace")


def assert_exact_controlled_inputs(link_map: Path, *, crt: Path, fixture: Path) -> None:
    text = link_map.read_text(encoding="utf-8", errors="replace")
    for required in (crt / "Scrt1.o", crt / "crti.o", fixture, crt / "crtn.o", MUSL_LIB / "libc.so"):
        if str(required) not in text:
            raise AssertionError(f"controlled link map omitted explicit input {required}")
    # `-nostdlib -nostartfiles` is only useful if the emitted map rejects the
    # host CRT/compiler-runtime paths too. The sole runtime input is pinned
    # musl libc; `Scrt1.o` must be the Rust-produced object, never musl's.
    loaded_inputs = "\n".join(
        line[5:] for line in text.splitlines() if line.startswith("LOAD ")
    )
    forbidden = ("crtbegin", "crtend", "libgcc", "libstdc++", "libasan", "libclang_rt", str(MUSL_SCRT1))
    for token in forbidden:
        if token in loaded_inputs:
            raise AssertionError(f"controlled dynamic PIE admitted ambient CRT/compiler input {token!r}")


def assert_elf_contract(path: Path) -> None:
    data, (entry, _), headers = elf_layout(path)
    interpreters = [header for header in headers if header[0] == PT_INTERP]
    if len(interpreters) != 1:
        raise AssertionError("controlled dynamic PIE must have exactly one PT_INTERP")
    _, _, offset, _, _, size, _, _ = interpreters[0]
    if data[offset : offset + size].rstrip(b"\0").decode() != str(MUSL_LOADER):
        raise AssertionError("controlled dynamic PIE has an ambient interpreter")
    if len([header for header in headers if header[0] == PT_DYNAMIC]) != 1:
        raise AssertionError("controlled dynamic PIE must have exactly one PT_DYNAMIC")

    dynamic = dynamic_text(path)
    needed = re.findall(r"Shared library: \[(.*?)\]", dynamic)
    if needed != ["libc.so"]:
        raise AssertionError(f"controlled dynamic PIE has ambient DT_NEEDED entries: {needed!r}")
    for tag in ("(INIT)", "(FINI)", "(INIT_ARRAY)", "(FINI_ARRAY)"):
        if tag not in dynamic:
            raise AssertionError(f"controlled dynamic PIE omitted lifecycle tag {tag}")

    symbols = symbol_table(path)
    for name in ("_start", "_init", "_fini", "__crabc_x86_64_dynamic_start", "main"):
        if name not in symbols or symbols[name][3] == "UND":
            raise AssertionError(f"controlled dynamic PIE omitted defined boundary {name}")
    if entry != symbols["_start"][0]:
        raise AssertionError("ELF entry does not point exactly at the Rust-produced _start")
    if symbols["_start"][1:3] != ("FUNC", "GLOBAL"):
        raise AssertionError("_start must remain a global function boundary")
    for name in ("_init", "_fini"):
        if symbols[name][1:3] != ("FUNC", "GLOBAL"):
            raise AssertionError(f"{name} must remain the global crti/crtn lifecycle boundary")

    dynamic_undefined = {
        name
        for name, (_, _, _, section) in symbols.items()
        if section == "UND"
    }
    allowed = {"__libc_start_main", "write", "_exit", "__crabc_x86_64_owned_crt_handoff"}
    unexpected = dynamic_undefined - allowed
    if unexpected:
        raise AssertionError(f"controlled dynamic PIE imported unexpected runtime symbols: {sorted(unexpected)!r}")
    if any(name in dynamic_undefined for name in ("__stack_chk_fail", "_Unwind_Resume")):
        raise AssertionError("controlled dynamic PIE imported an ambient compiler/runtime helper")


@unittest.skipUnless(
    native_x86_64_evidence(),
    "requires the dedicated native Linux/x86-64 dynamic CRT link-contract runner",
)
class X86_64DynamicLinkContractTests(unittest.TestCase):
    def test_rust_crt_objects_form_one_closed_dynamic_pie_handoff(self) -> None:
        for required in (MUSL_LOADER, MUSL_LIB / "libc.so", MUSL_SPECS):
            self.assertTrue(required.is_file(), f"missing pinned musl input: {required}")

        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            crt = build_candidate_crt(work)
            fixture = build_fixture_object(work)
            candidate = work / "controlled-dynamic-pie"
            link_map = work / "controlled-dynamic-pie.map"
            link_controlled_dynamic_pie(candidate, crt=crt, fixture=fixture, link_map=link_map)
            assert_exact_controlled_inputs(link_map, crt=crt, fixture=fixture)
            assert_elf_contract(candidate)

            launched = run([str(candidate)])
            self.assertEqual(launched.returncode, 0, launched.stderr.decode(errors="replace"))
            self.assertEqual(launched.stdout, b"IMF")


if __name__ == "__main__":
    unittest.main()
