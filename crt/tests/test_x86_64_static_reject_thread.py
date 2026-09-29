#!/usr/bin/env python3
"""Execute a malformed CRT finalizer boundary in installed static products."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "crt/fixtures/x86_64_static_reject_thread.c"
MODES = (("-static", "crt1.o", "ET_EXEC"), ("-static-pie", "rcrt1.o", "ET_DYN"))


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode:
        raise AssertionError(f"command failed ({result.returncode}): {command}\n{result.stderr}")
    return result


def symbol_address(binary: Path, name: str) -> int:
    lines = run(["nm", "-n", str(binary)]).stdout.splitlines()
    matches = [int(fields[0], 16) for line in lines
               if (fields := line.split()) and len(fields) == 3 and fields[2] == name]
    if len(matches) != 1:
        raise AssertionError(f"expected one {name} in {binary}")
    return matches[0]


def corrupt_fini_boundary(binary: Path, output: Path) -> None:
    """Make the installed CRT's returned fini end one byte misaligned."""
    data = bytearray(binary.read_bytes())
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[0][:6] != b"\x7fELF\x02\x01" or header[2] != 62:
        raise AssertionError("expected x86-64 ELF64 executable")
    address = symbol_address(binary, "__crabc_fini_array_end_address")
    for index in range(header[10]):
        kind, _, offset, virtual, _, file_size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, header[5] + index * header[9]
        )
        if kind != 1 or not virtual <= address or address + 7 > virtual + file_size:
            continue
        instruction = offset + address - virtual
        if data[instruction:instruction + 3] != b"\x48\x8d\x05":
            raise AssertionError("installed CRT fini-end bridge changed instruction form")
        displacement = struct.unpack_from("<i", data, instruction + 3)[0]
        struct.pack_into("<i", data, instruction + 3, displacement + 1)
        output.write_bytes(data)
        output.chmod(0o755)
        return
    raise AssertionError("CRT fini-end bridge is outside a file-backed PT_LOAD")


def check(sysroot: Path, work: Path) -> None:
    driver = sysroot / "bin/crabc-cc"
    if not driver.is_file():
        raise AssertionError(f"missing installed driver: {driver}")
    for flag, crt, elf_type in MODES:
        mode = crt.removesuffix(".o")
        object_file = work / f"{mode}.application.o"
        binary = work / mode
        receipt_file = work / f"{mode}.link.json"
        malformed = work / f"{mode}.malformed"
        run([str(driver), flag, "-std=c11", "-pthread", "-c", str(FIXTURE), "-o", str(object_file)])
        run([str(driver), flag, "--link-receipt", str(receipt_file.relative_to(ROOT)),
             str(object_file), "-o", str(binary)])
        receipt = json.loads(receipt_file.read_text())
        if receipt["mode"]["crt_object"] != crt or receipt["mode"]["elf_type"] != elf_type:
            raise AssertionError("installed driver selected the wrong static entry")
        paths = {entry["path"] for entry in receipt["input_receipts"]}
        if {f"usr/lib/{crt}", "usr/lib/libc.a", "usr/lib/libcrabc-builtins.a"} - paths:
            raise AssertionError("installed link omitted an owned runtime input")
        control = subprocess.run([str(binary)], capture_output=True, timeout=3, check=False)
        if control.returncode != 0:
            raise AssertionError(f"{mode} control exited {control.returncode}: {control.stderr!r}")
        corrupt_fini_boundary(binary, malformed)
        rejected = subprocess.run([str(malformed)], capture_output=True, timeout=3, check=False)
        if rejected.returncode != 127:
            raise AssertionError(f"{mode} malformed finalizer exited {rejected.returncode}, expected 127")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sysroot", type=Path, nargs="+")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise SystemExit("native Linux/x86-64 is required")
    for sysroot in args.sysroot:
        with tempfile.TemporaryDirectory(prefix="crt-static-reject-", dir=ROOT / ".work") as temporary:
            check(sysroot.resolve(), Path(temporary))
        print(f"installed static CRT rejects with process exit: PASS ({sysroot})")


if __name__ == "__main__":
    main()
