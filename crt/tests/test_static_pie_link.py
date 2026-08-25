#!/usr/bin/env python3
"""Link-level proof that rcrt1 is a real static-PIE startup object."""

from __future__ import annotations

import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


CRT_ROOT = Path(__file__).resolve().parents[1]
ROOT = CRT_ROOT.parent
BUILDER = CRT_ROOT / "build.py"
FIXTURE = CRT_ROOT / "fixtures" / "static_pie_fixture.rs"
TARGET = "aarch64-unknown-linux-musl"
PINNED_TOOLCHAIN = "nightly-2026-07-24"

PT_DYNAMIC = 2
PT_INTERP = 3
ET_DYN = 3
EM_AARCH64 = 183
DT_NULL = 0
DT_NEEDED = 1
DT_RELA = 7
DT_RELR = 36


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


def inspect_static_pie(path: Path, *, packed_relr: bool) -> None:
    data = path.read_bytes()
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    _, elf_type, machine, _, _, program_offset, _, _, _, program_size, program_count, *_ = header
    if elf_type != ET_DYN or machine != EM_AARCH64:
        raise AssertionError(f"expected AArch64 ET_DYN static PIE, got type={elf_type} machine={machine}")
    dynamic: tuple[int, int] | None = None
    interpreter_found = False
    for index in range(program_count):
        offset = program_offset + index * program_size
        program_type, _, file_offset, _, _, file_size, _, _ = struct.unpack_from("<IIQQQQQQ", data, offset)
        if program_type == PT_INTERP:
            interpreter_found = True
        if program_type == PT_DYNAMIC:
            dynamic = (file_offset, file_size)
    if interpreter_found:
        raise AssertionError("static PIE unexpectedly has PT_INTERP")
    if dynamic is None:
        raise AssertionError("static PIE lacks PT_DYNAMIC relocation metadata")
    dynamic_offset, dynamic_size = dynamic
    needed = False
    tags: set[int] = set()
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
        tag, _ = struct.unpack_from("<qQ", data, offset)
        if tag == DT_NULL:
            break
        tags.add(tag)
        if tag == DT_NEEDED:
            needed = True
    if needed:
        raise AssertionError("static PIE unexpectedly has DT_NEEDED")
    if packed_relr:
        if DT_RELR not in tags:
            raise AssertionError("packed static PIE lacks DT_RELR")
    elif DT_RELA not in tags:
        raise AssertionError("static PIE lacks DT_RELA")


class StaticPieLinkTests(unittest.TestCase):
    def test_rcrt1_links_as_dependency_free_static_pie(self) -> None:
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

            fixture_object = work / "static_pie_fixture.o"
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

            variants = (
                ("rela", (), False),
                ("relr", ("--pack-dyn-relocs=relr",), True),
            )
            for name, relocation_arguments, packed_relr in variants:
                executable = work / ("static-pie-" + name)
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
                self.assertEqual(
                    link.returncode,
                    0,
                    link.stderr.decode(errors="replace"),
                )
                inspect_static_pie(executable, packed_relr=packed_relr)
                if platform.system() == "Linux" and platform.machine() == "aarch64":
                    execute = subprocess.run(
                        [str(executable)],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertEqual(
                        execute.returncode,
                        0,
                        execute.stderr.decode(errors="replace"),
                    )


if __name__ == "__main__":
    unittest.main()
