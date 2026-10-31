#!/usr/bin/env python3
"""Retain one installed-header object and four owned links for native ABI imports."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
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

MODES = ("static", "static-pie", "dynamic-pie", "dynamic-non-pie")
REPORT_KEYS = frozenset({
    "schema", "source_sha256", "source", "static_product", "dynamic_product",
    "dynamic_driver_sha256", "static_driver_sha256", "workload_sha256",
    "workload_rows", "commands", "links"})


class ImportReceiptError(RuntimeError):
    """The retained object or an owned link no longer binds to its source."""


@dataclass(frozen=True)
class TailCall:
    key: str
    alias: str
    provider: str
    alias_size: int
    prefix: bytes
    call_offset: int


@dataclass(frozen=True)
class Row:
    name: str
    schema: str
    fixture: str
    imports: tuple[str, ...]
    loader_checks: tuple[tuple[str, str], ...] = ()
    tail_call: TailCall | None = None

    @property
    def loader_symbols(self) -> frozenset[str]:
        return frozenset(symbol for _, symbol in self.loader_checks)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ImportReceiptError(message)


def build_rows(rows: tuple[Row, ...]) -> dict[str, Row]:
    table: dict[str, Row] = {}
    for row in rows:
        require(row.name not in table, f"duplicate native ABI import row {row.name}")
        require((row.schema, row.fixture) == (
            f"crabc.x86_64-native-abi-{row.name}-import-receipt/v1",
            f"native_abi_{row.name}_import_fixture.c"), f"row {row.name} differs")
        require(row.imports and len(set(row.imports)) == len(row.imports),
                f"workload imports for {row.name} differ")
        require(len({key for key, _ in row.loader_checks}) == len(row.loader_checks),
                f"loader reports for {row.name} differ")
        table[row.name] = row
    return table


ROWS = build_rows((
    Row("btowc", "crabc.x86_64-native-abi-btowc-import-receipt/v1",
        "native_abi_btowc_import_fixture.c", ("btowc",)),
    Row("fchdir", "crabc.x86_64-native-abi-fchdir-import-receipt/v1",
        "native_abi_fchdir_import_fixture.c", ("nftw",)),
    Row("memcmp", "crabc.x86_64-native-abi-memcmp-import-receipt/v1",
        "native_abi_memcmp_import_fixture.c", ("memcmp", "bcmp"),
        loader_checks=(("loader_occurrence", "memcmp"), ("bcmp_loader_occurrence", "bcmp")),
        tail_call=TailCall("shared_bcmp_direct_call", "bcmp", "memcmp", 5, b"\xe9", 0)),
    Row("memmove", "crabc.x86_64-native-abi-memmove-import-receipt/v1",
        "native_abi_memmove_import_fixture.c", ("memmove", "realpath", "bcopy"),
        loader_checks=(("loader_occurrence", "memmove"),),
        tail_call=TailCall("shared_bcopy_direct_call", "bcopy", "memmove", 8, b"\x48\x87\xfe\xe9", 3)),
    Row("strlen", "crabc.x86_64-native-abi-strlen-import-receipt/v1",
        "native_abi_strlen_import_fixture.c", ("strlen", "gethostbyname")),
    Row("wcsrtombs", "crabc.x86_64-native-abi-wcsrtombs-import-receipt/v1",
        "native_abi_wcsrtombs_import_fixture.c", ("wcstombs", "wcsrtombs")),
    Row("wctomb", "crabc.x86_64-native-abi-wctomb-import-receipt/v1",
        "native_abi_wctomb_import_fixture.c", ("fwscanf", "wctomb")),
))


def row_for(symbol: str) -> Row:
    require(symbol in ROWS, f"unknown native ABI import symbol {symbol}")
    return ROWS[symbol]


def regular(path: Path, description: str) -> Path:
    try:
        return inventory.physical_regular(path, description)
    except inventory.InventoryError as error:
        raise ImportReceiptError(str(error)) from error


def directory(path: Path, description: str) -> Path:
    try:
        return inventory.physical_directory(path, description)
    except inventory.InventoryError as error:
        raise ImportReceiptError(str(error)) from error


def digest(path: Path) -> str:
    return hashlib.sha256(regular(path, str(path)).read_bytes()).hexdigest()


def workload_rows(path: Path, symbol: str) -> dict[str, Any]:
    row = row_for(symbol)
    symbols = subprocess.run(("/usr/bin/readelf", "-Ws", str(path)), capture_output=True, text=True, check=False)
    relocations = subprocess.run(("/usr/bin/readelf", "-rW", str(path)), capture_output=True, text=True, check=False)
    require(symbols.returncode == relocations.returncode == 0, f"{row.name} workload ELF is unreadable")
    rows = {}
    for name in row.imports:
        selected = [line.split() for line in symbols.stdout.splitlines()
                    if line.endswith(" " + name) and line.split()[0].endswith(":")]
        require(len(selected) == 1 and selected[0][3:7] == ["NOTYPE", "GLOBAL", "DEFAULT", "UND"],
                f"{row.name} workload {name} import differs")
        calls = [line for line in relocations.stdout.splitlines()
                 if re.search(rf"\b{re.escape(name)}\s+-\s+4\b", line)]
        require(calls and all(re.search(r"\bR_X86_64_(PLT32|GOTPCREL)\b", line) for line in calls),
                f"{row.name} workload {name} relocation differs")
        rows[name] = {"symbol": selected[0], "relocations": calls}
    require(not re.search(r"\bR_X86_64_(32|32S)\b", relocations.stdout),
            f"{row.name} workload retains an absolute 32-bit relocation")
    return rows


def loader_occurrence(dynamic_product: Path, row: Row, symbol: str) -> dict[str, Any]:
    message = "comparison loader symbol differs" if row.name == "memcmp" else f"{row.name} loader symbol differs"
    require(symbol in row.loader_symbols, message)
    loader = regular(dynamic_product / "lib/ld-crabc-x86_64.so.1", f"{symbol} loader")
    symbols = subprocess.run(("/usr/bin/readelf", "--dyn-syms", "-W", str(loader)),
                             capture_output=True, text=True, check=False)
    relocations = subprocess.run(("/usr/bin/readelf", "-rW", str(loader)),
                                 capture_output=True, text=True, check=False)
    require(symbols.returncode == relocations.returncode == 0,
            f"{symbol} loader ELF is unreadable")
    rows = [line.split() for line in symbols.stdout.splitlines()
            if line.endswith(" " + symbol) and line.split()[0].endswith(":")]
    require(len(rows) == 1 and rows[0][3:6] == ["FUNC", "GLOBAL", "DEFAULT"]
            and rows[0][6].isdigit() and int(rows[0][1], 16) > 0
            and int(rows[0][2]) > 0
            and not re.search(rf"\b{re.escape(symbol)}\b", relocations.stdout),
            f"{symbol} loader occurrence differs")
    return {"loader_sha256": digest(loader), "address": int(rows[0][1], 16),
            "size_bytes": int(rows[0][2]), "section_index": rows[0][6]}


def shared_tail_call(dynamic_product: Path, symbol: str) -> dict[str, Any]:
    """Bind the shared alias tail branch that has no provider GOT relocation."""
    row = row_for(symbol)
    spec = row.tail_call
    libc = regular(dynamic_product / "usr/lib/libc.so", f"{row.name} shared libc")
    symbols = subprocess.run(("/usr/bin/readelf", "-Ws", str(libc)),
                             capture_output=True, text=True, check=False)
    require(symbols.returncode == 0, f"{row.name} shared symbol table is unreadable")
    addresses = {}
    for name in (spec.alias, spec.provider):
        rows = [line.split() for line in symbols.stdout.splitlines()
                if line.endswith(" " + name) and line.split()[0].endswith(":")]
        require(len(rows) == 2 and all(row[3:6] == ["FUNC", "GLOBAL", "DEFAULT"]
                                       and row[6].isdigit() for row in rows)
                and len({(row[1], row[2], row[6]) for row in rows}) == 1,
                f"{row.name} shared {name} provider rows differ")
        addresses[name] = (int(rows[0][1], 16), int(rows[0][2]))
    alias_address, alias_size = addresses[spec.alias]
    provider_address, _provider_size = addresses[spec.provider]
    require(alias_address > 0 and alias_size == spec.alias_size and provider_address > 0,
            f"{row.name} shared {spec.alias} or provider address differs")
    try:
        body = boundary._public_weak_virtual_bytes(
            libc.read_bytes(), alias_address, alias_size, 3, executable=True)
    except boundary.AllocatorBoundaryError as error:
        raise ImportReceiptError(str(error)) from error
    require(body[:len(spec.prefix)] == spec.prefix
            and alias_address + spec.alias_size
            + struct.unpack_from("<i", body, len(spec.prefix))[0] == provider_address,
            f"{row.name} shared {spec.alias} tail branch resolves elsewhere")
    return {"libc_sha256": digest(libc), f"{spec.alias}_address": alias_address,
            "call_address": alias_address + spec.call_offset,
            "provider_address": provider_address, "branch_kind": "direct-tail-jump"}


def compile_command(dynamic_product: Path, work: Path, symbol: str) -> list[str]:
    return [str(dynamic_product / "bin/crabc-cc-dynamic"), "--dynamic-pie", "-std=c11", "-fno-builtin",
            "-fno-stack-protector", "-c", str(MODULE_DIR / ROWS[symbol].fixture), "-o", str(work / "workload.o")]


def link_command(mode: str, static_product: Path, dynamic_product: Path, work: Path) -> list[str]:
    if mode.startswith("static"):
        return [str(static_product / "bin/crabc-cc"), "-" + mode, "--link-receipt", mode + ".receipt.json",
                str(work / "workload.o"), "-o", str(work / mode)]
    return [str(dynamic_product / "bin/crabc-cc-dynamic"), "--" + mode,
            str(work / "workload.o"), "-o", str(work / mode)]


def link_receipt(mode: str, work: Path) -> Path:
    return work / (mode + (".receipt.json" if mode.startswith("static") else ".crabc-link.json"))


def capture(command: list[str], work: Path, label: str, symbol: str) -> dict[str, Any]:
    result = subprocess.run(command, cwd=work, capture_output=True, check=False)
    (work / (label + ".stdout")).write_bytes(result.stdout)
    (work / (label + ".stderr")).write_bytes(result.stderr)
    (work / (label + ".status")).write_text(f"{result.returncode}\n", encoding="ascii")
    require(result.returncode == 0, f"{symbol} {label} failed: {result.stderr.decode(errors='replace')}")
    return {"argv": command, "stdout_sha256": digest(work / (label + ".stdout")),
            "stderr_sha256": digest(work / (label + ".stderr")), "status": result.returncode}


def observations(row: Row, dynamic_product: Path) -> dict[str, Any]:
    found = {key: loader_occurrence(dynamic_product, row, symbol) for key, symbol in row.loader_checks}
    if row.tail_call is not None:
        found[row.tail_call.key] = shared_tail_call(dynamic_product, row.name)
    return found


def collect(static_product: Path, dynamic_product: Path, output: Path, symbol: str) -> dict[str, Any]:
    row = row_for(symbol)
    output = output.absolute()
    require(output.is_relative_to(inventory.ROOT / ".work") and not output.exists()
            and output.parent.resolve() == output.parent, f"{row.name} output must be a fresh physical .work child")
    static_product = directory(static_product.absolute(), f"{row.name} static product")
    dynamic_product = directory(dynamic_product.absolute(), f"{row.name} dynamic product")
    source_before = digest(MODULE_DIR / row.fixture)
    output.mkdir(mode=0o700)
    commands = {"compile": capture(compile_command(dynamic_product, output, row.name),
                                   output, "compile", row.name)}
    require(digest(MODULE_DIR / row.fixture) == source_before, f"{row.name} source changed during compilation")
    rows = workload_rows(output / "workload.o", row.name)
    for mode in MODES:
        commands[mode] = capture(link_command(mode, static_product, dynamic_product, output),
                                 output, mode, row.name)
    report = {"schema": row.schema, "source_sha256": source_before,
              "source": inventory.collector_source_seal(),
              "static_product": str(static_product), "dynamic_product": str(dynamic_product),
              "dynamic_driver_sha256": digest(dynamic_product / "bin/crabc-cc-dynamic"),
              "static_driver_sha256": digest(static_product / "bin/crabc-cc"),
              "workload_sha256": digest(output / "workload.o"),
              "workload_rows": rows, **observations(row, dynamic_product),
              "commands": commands,
              "links": {mode: product_evidence.validate_link(
                  static_product if mode.startswith("static") else dynamic_product,
                  output / "workload.o", output / mode, link_receipt(mode, output),
                  mode.removeprefix("dynamic-")) for mode in MODES}}
    require(digest(MODULE_DIR / row.fixture) == source_before, f"{row.name} source changed during linking")
    (output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report


def validate_report(report_path: Path, *, static_product: Path, dynamic_product: Path,
                    symbol: str) -> dict[str, Any]:
    row = row_for(symbol)
    report_path = regular(report_path.absolute(), f"{row.name} import report")
    require(report_path.name == "report.json", f"{row.name} report filename differs")
    work = directory(report_path.parent, f"{row.name} retained work")
    static_product = directory(static_product.absolute(), f"{row.name} static product")
    dynamic_product = directory(dynamic_product.absolute(), f"{row.name} dynamic product")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    extras = {key for key, _ in row.loader_checks}
    if row.tail_call is not None:
        extras.add(row.tail_call.key)
    require(type(report) is dict and set(report) == set(REPORT_KEYS) | extras,
            f"{row.name} report shape differs")
    require(report["schema"] == row.schema and report["source_sha256"] == digest(MODULE_DIR / row.fixture)
            and report["source"] == inventory.collector_source_seal()
            and report["static_product"] == str(static_product)
            and report["dynamic_product"] == str(dynamic_product)
            and report["dynamic_driver_sha256"] == digest(dynamic_product / "bin/crabc-cc-dynamic")
            and report["static_driver_sha256"] == digest(static_product / "bin/crabc-cc")
            and report["workload_sha256"] == digest(work / "workload.o")
            and report["workload_rows"] == workload_rows(work / "workload.o", row.name)
            and all(report[key] == value
                    for key, value in observations(row, dynamic_product).items()),
            f"{row.name} source, products, or workload changed")
    require(set(report["commands"]) == {"compile", *MODES}
            and set(report["links"]) == set(MODES), f"{row.name} command or link roster differs")
    for label in ("compile", *MODES):
        command = report["commands"][label]
        expected_argv = compile_command(dynamic_product, work, row.name) if label == "compile" else link_command(
            label, static_product, dynamic_product, work)
        require(type(command) is dict and set(command) == {
            "argv", "stdout_sha256", "stderr_sha256", "status"}
            and command["argv"] == expected_argv and command["status"] == 0
            and command["stdout_sha256"] == digest(work / (label + ".stdout"))
            and command["stderr_sha256"] == digest(work / (label + ".stderr"))
            and regular(work / (label + ".status"), label + " status").read_bytes() == b"0\n",
            f"{row.name} {label} transcript changed")
    for mode in MODES:
        expected = product_evidence.validate_link(
            static_product if mode.startswith("static") else dynamic_product,
            work / "workload.o", work / mode, link_receipt(mode, work),
            mode.removeprefix("dynamic-"))
        require(report["links"][mode] == expected, f"{row.name} {mode} link changed")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    modes = parser.add_subparsers(dest="mode", required=True)
    for name in ("collect", "validate-report"):
        item = modes.add_parser(name, allow_abbrev=False)
        item.add_argument("--symbol", required=True)
        item.add_argument("--static-product", required=True, type=Path)
        item.add_argument("--dynamic-product", required=True, type=Path)
        if name == "collect":
            item.add_argument("--output", required=True, type=Path)
        else:
            item.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.mode == "collect":
            collect(args.static_product, args.dynamic_product, args.output, args.symbol)
        else:
            validate_report(args.report, static_product=args.static_product,
                            dynamic_product=args.dynamic_product, symbol=args.symbol)
    except (ImportReceiptError, OSError, ValueError, product_evidence.ProductEvidenceError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(f"native ABI {args.symbol} imports: PASS (source-bound owned links)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
