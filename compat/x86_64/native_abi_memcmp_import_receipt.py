#!/usr/bin/env python3
"""Retain one installed-header object and four owned links for memcmp imports."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
from typing import Any

sys.dont_write_bytecode = True
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import native_abi_inventory as inventory
import owned_posix_product_evidence as product_evidence
import native_c_allocator_boundary as boundary

ROOT = inventory.ROOT
SOURCE = MODULE_DIR / "native_abi_memcmp_import_fixture.c"
SCHEMA = "crabc.x86_64-native-abi-memcmp-import-receipt/v1"
MODES = ("static", "static-pie", "dynamic-pie", "dynamic-non-pie")
COMPILE_FLAGS = ("--dynamic-pie", "-std=c11", "-fno-builtin", "-fno-stack-protector")


class MemcmpImportError(RuntimeError):
    """The retained object or an owned link no longer binds to its source."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MemcmpImportError(message)


def regular(path: Path, description: str) -> Path:
    try:
        return inventory.physical_regular(path, description)
    except inventory.InventoryError as error:
        raise MemcmpImportError(str(error)) from error


def directory(path: Path, description: str) -> Path:
    try:
        return inventory.physical_directory(path, description)
    except inventory.InventoryError as error:
        raise MemcmpImportError(str(error)) from error


def digest(path: Path) -> str:
    return hashlib.sha256(regular(path, str(path)).read_bytes()).hexdigest()


def workload_rows(path: Path) -> dict[str, Any]:
    symbols = subprocess.run(("/usr/bin/readelf", "-Ws", str(path)), capture_output=True, text=True, check=False)
    relocations = subprocess.run(("/usr/bin/readelf", "-rW", str(path)), capture_output=True, text=True, check=False)
    require(symbols.returncode == relocations.returncode == 0, "memcmp workload ELF is unreadable")
    rows = {}
    for name in ("memcmp", "bcmp"):
        selected = [line.split() for line in symbols.stdout.splitlines()
                    if line.endswith(" " + name) and line.split()[0].endswith(":")]
        require(len(selected) == 1 and selected[0][3:7] == ["NOTYPE", "GLOBAL", "DEFAULT", "UND"],
                f"memcmp workload {name} import differs")
        calls = [line for line in relocations.stdout.splitlines()
                 if re.search(rf"\b{re.escape(name)}\s+-\s+4\b", line)]
        require(calls and all(re.search(r"\bR_X86_64_(PLT32|GOTPCREL)\b", line) for line in calls),
                f"memcmp workload {name} relocation differs")
        rows[name] = {"symbol": selected[0], "relocations": calls}
    require(not re.search(r"\bR_X86_64_(32|32S)\b", relocations.stdout),
            "memcmp workload retains an absolute 32-bit relocation")
    return rows


def loader_occurrence(dynamic_product: Path, name: str = "memcmp") -> dict[str, Any]:
    require(name in {"memcmp", "bcmp"}, "comparison loader symbol differs")
    loader = regular(dynamic_product / "lib/ld-crabc-x86_64.so.1", "memcmp loader")
    symbols = subprocess.run(("/usr/bin/readelf", "--dyn-syms", "-W", str(loader)),
                             capture_output=True, text=True, check=False)
    relocations = subprocess.run(("/usr/bin/readelf", "-rW", str(loader)),
                                 capture_output=True, text=True, check=False)
    require(symbols.returncode == relocations.returncode == 0,
            "memcmp loader ELF is unreadable")
    rows = [line.split() for line in symbols.stdout.splitlines()
            if line.endswith(" " + name) and line.split()[0].endswith(":" )]
    require(len(rows) == 1 and rows[0][3:6] == ["FUNC", "GLOBAL", "DEFAULT"]
            and rows[0][6].isdigit() and int(rows[0][1], 16) > 0
            and int(rows[0][2]) > 0
            and not re.search(rf"\b{re.escape(name)}\b", relocations.stdout),
            f"{name} loader occurrence differs")
    return {"loader_sha256": digest(loader), "address": int(rows[0][1], 16),
            "size_bytes": int(rows[0][2]), "section_index": rows[0][6]}


def shared_bcmp_direct_call(dynamic_product: Path) -> dict[str, Any]:
    """Bind the shared bcmp tail branch that has no memcmp GOT relocation."""
    libc = regular(dynamic_product / "usr/lib/libc.so", "memcmp shared libc")
    symbols = subprocess.run(("/usr/bin/readelf", "-Ws", str(libc)),
                             capture_output=True, text=True, check=False)
    require(symbols.returncode == 0, "memcmp shared symbol table is unreadable")
    addresses = {}
    for name in ("bcmp", "memcmp"):
        rows = [line.split() for line in symbols.stdout.splitlines()
                if line.endswith(" " + name) and line.split()[0].endswith(":" )]
        require(len(rows) == 2 and all(row[3:6] == ["FUNC", "GLOBAL", "DEFAULT"]
                                       and row[6].isdigit() for row in rows)
                and len({(row[1], row[2], row[6]) for row in rows}) == 1,
                f"memcmp shared {name} provider rows differ")
        addresses[name] = (int(rows[0][1], 16), int(rows[0][2]))
    bcmp_address, bcmp_size = addresses["bcmp"]
    provider_address, _provider_size = addresses["memcmp"]
    require(bcmp_address > 0 and bcmp_size == 5 and provider_address > 0,
            "memcmp shared bcmp or provider address differs")
    try:
        body = boundary._public_weak_virtual_bytes(
            libc.read_bytes(), bcmp_address, bcmp_size, 3, executable=True)
    except boundary.AllocatorBoundaryError as error:
        raise MemcmpImportError(str(error)) from error
    require(body[0] == 0xe9
            and bcmp_address + 5 + struct.unpack_from("<i", body, 1)[0] == provider_address,
            "memcmp shared bcmp tail branch resolves elsewhere")
    return {"libc_sha256": digest(libc), "bcmp_address": bcmp_address,
            "call_address": bcmp_address, "provider_address": provider_address,
            "branch_kind": "direct-tail-jump"}


def compile_command(dynamic_product: Path, work: Path) -> list[str]:
    return [str(dynamic_product / "bin/crabc-cc-dynamic"), *COMPILE_FLAGS,
            "-c", str(SOURCE), "-o", str(work / "workload.o")]


def link_command(mode: str, static_product: Path, dynamic_product: Path, work: Path) -> list[str]:
    if mode.startswith("static"):
        return [str(static_product / "bin/crabc-cc"), "-" + mode,
                "--link-receipt", mode + ".receipt.json",
                str(work / "workload.o"), "-o", str(work / mode)]
    return [str(dynamic_product / "bin/crabc-cc-dynamic"), "--" + mode,
            str(work / "workload.o"), "-o", str(work / mode)]


def link_receipt(mode: str, work: Path) -> Path:
    return work / (mode + (".receipt.json" if mode.startswith("static") else ".crabc-link.json"))


def capture(command: list[str], work: Path, label: str) -> dict[str, Any]:
    result = subprocess.run(command, cwd=work, capture_output=True, check=False)
    (work / (label + ".stdout")).write_bytes(result.stdout)
    (work / (label + ".stderr")).write_bytes(result.stderr)
    (work / (label + ".status")).write_text(f"{result.returncode}\n", encoding="ascii")
    require(result.returncode == 0, f"memcmp {label} failed: {result.stderr.decode(errors='replace')}")
    return {"argv": command, "stdout_sha256": digest(work / (label + ".stdout")),
            "stderr_sha256": digest(work / (label + ".stderr")), "status": result.returncode}


def collect(static_product: Path, dynamic_product: Path, output: Path) -> dict[str, Any]:
    output = output.absolute()
    require(output.is_relative_to(ROOT / ".work") and not output.exists()
            and output.parent.resolve() == output.parent, "memcmp output must be a fresh physical .work child")
    static_product = directory(static_product.absolute(), "memcmp static product")
    dynamic_product = directory(dynamic_product.absolute(), "memcmp dynamic product")
    source_before = digest(SOURCE)
    output.mkdir(mode=0o700)
    commands = {"compile": capture(compile_command(dynamic_product, output), output, "compile")}
    require(digest(SOURCE) == source_before, "memcmp source changed during compilation")
    rows = workload_rows(output / "workload.o")
    for mode in MODES:
        commands[mode] = capture(link_command(mode, static_product, dynamic_product, output), output, mode)
    report = {"schema": SCHEMA, "source_sha256": source_before,
              "source": inventory.collector_source_seal(),
              "static_product": str(static_product), "dynamic_product": str(dynamic_product),
              "dynamic_driver_sha256": digest(dynamic_product / "bin/crabc-cc-dynamic"),
              "static_driver_sha256": digest(static_product / "bin/crabc-cc"),
              "workload_sha256": digest(output / "workload.o"),
              "workload_rows": rows, "loader_occurrence": loader_occurrence(dynamic_product),
              "bcmp_loader_occurrence": loader_occurrence(dynamic_product, "bcmp"),
              "shared_bcmp_direct_call": shared_bcmp_direct_call(dynamic_product),
              "commands": commands,
              "links": {mode: product_evidence.validate_link(
                  static_product if mode.startswith("static") else dynamic_product,
                  output / "workload.o", output / mode, link_receipt(mode, output),
                  mode.removeprefix("dynamic-")) for mode in MODES}}
    require(digest(SOURCE) == source_before, "memcmp source changed during linking")
    (output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report


def validate_report(report_path: Path, *, static_product: Path, dynamic_product: Path) -> dict[str, Any]:
    report_path = regular(report_path.absolute(), "memcmp import report")
    require(report_path.name == "report.json", "memcmp report filename differs")
    work = directory(report_path.parent, "memcmp retained work")
    static_product = directory(static_product.absolute(), "memcmp static product")
    dynamic_product = directory(dynamic_product.absolute(), "memcmp dynamic product")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    require(type(report) is dict and set(report) == {
        "schema", "source_sha256", "source", "static_product", "dynamic_product",
        "dynamic_driver_sha256", "static_driver_sha256", "workload_sha256",
        "workload_rows", "loader_occurrence", "bcmp_loader_occurrence", "shared_bcmp_direct_call",
        "commands", "links"}, "memcmp report shape differs")
    require(report["schema"] == SCHEMA and report["source_sha256"] == digest(SOURCE)
            and report["source"] == inventory.collector_source_seal()
            and report["static_product"] == str(static_product)
            and report["dynamic_product"] == str(dynamic_product)
            and report["dynamic_driver_sha256"] == digest(dynamic_product / "bin/crabc-cc-dynamic")
            and report["static_driver_sha256"] == digest(static_product / "bin/crabc-cc")
            and report["workload_sha256"] == digest(work / "workload.o")
            and report["workload_rows"] == workload_rows(work / "workload.o")
            and report["loader_occurrence"] == loader_occurrence(dynamic_product)
            and report["bcmp_loader_occurrence"] == loader_occurrence(dynamic_product, "bcmp")
            and report["shared_bcmp_direct_call"] == shared_bcmp_direct_call(dynamic_product),
            "memcmp source, products, or workload changed")
    require(set(report["commands"]) == {"compile", *MODES}
            and set(report["links"]) == set(MODES), "memcmp command or link roster differs")
    for label in ("compile", *MODES):
        command = report["commands"][label]
        expected_argv = (compile_command(dynamic_product, work) if label == "compile"
                         else link_command(label, static_product, dynamic_product, work))
        require(type(command) is dict and set(command) == {
            "argv", "stdout_sha256", "stderr_sha256", "status"}
            and command["argv"] == expected_argv and command["status"] == 0
            and command["stdout_sha256"] == digest(work / (label + ".stdout"))
            and command["stderr_sha256"] == digest(work / (label + ".stderr"))
            and regular(work / (label + ".status"), label + " status").read_bytes() == b"0\n",
            f"memcmp {label} transcript changed")
    for mode in MODES:
        expected = product_evidence.validate_link(
            static_product if mode.startswith("static") else dynamic_product,
            work / "workload.o", work / mode, link_receipt(mode, work),
            mode.removeprefix("dynamic-"))
        require(report["links"][mode] == expected, f"memcmp {mode} link changed")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    modes = parser.add_subparsers(dest="mode", required=True)
    for name in ("collect", "validate-report"):
        item = modes.add_parser(name, allow_abbrev=False)
        item.add_argument("--static-product", required=True, type=Path)
        item.add_argument("--dynamic-product", required=True, type=Path)
        if name == "collect":
            item.add_argument("--output", required=True, type=Path)
        else:
            item.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.mode == "collect":
            collect(args.static_product, args.dynamic_product, args.output)
        else:
            validate_report(args.report, static_product=args.static_product,
                            dynamic_product=args.dynamic_product)
    except (MemcmpImportError, OSError, ValueError, product_evidence.ProductEvidenceError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print("native ABI memcmp imports: PASS (source-bound owned links)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
