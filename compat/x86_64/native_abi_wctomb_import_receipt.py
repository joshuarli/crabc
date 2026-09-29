#!/usr/bin/env python3
"""Retain the wide-printer caller and four owned links for wctomb imports."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

sys.dont_write_bytecode = True
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import native_abi_inventory as inventory
import owned_posix_product_evidence as product_evidence

ROOT = inventory.ROOT
SOURCE = MODULE_DIR / "native_abi_wctomb_import_fixture.c"
SCHEMA = "crabc.x86_64-native-abi-wctomb-import-receipt/v1"
MODES = ("static", "static-pie", "dynamic-pie", "dynamic-non-pie")
COMPILE_FLAGS = ("--dynamic-pie", "-std=c11", "-fno-builtin", "-fno-stack-protector")


class WctombImportError(RuntimeError):
    """The retained object or an owned link no longer binds to its source."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WctombImportError(message)


def regular(path: Path, description: str) -> Path:
    try:
        return inventory.physical_regular(path, description)
    except inventory.InventoryError as error:
        raise WctombImportError(str(error)) from error


def directory(path: Path, description: str) -> Path:
    try:
        return inventory.physical_directory(path, description)
    except inventory.InventoryError as error:
        raise WctombImportError(str(error)) from error


def digest(path: Path) -> str:
    return hashlib.sha256(regular(path, str(path)).read_bytes()).hexdigest()


def workload_rows(path: Path) -> dict[str, Any]:
    symbols = subprocess.run(("/usr/bin/readelf", "-Ws", str(path)), capture_output=True, text=True, check=False)
    relocations = subprocess.run(("/usr/bin/readelf", "-rW", str(path)), capture_output=True, text=True, check=False)
    require(symbols.returncode == relocations.returncode == 0, "wctomb workload ELF is unreadable")
    require(not any(line.endswith(" wctomb") for line in symbols.stdout.splitlines())
            and not re.search(r"\bwctomb\b", relocations.stdout),
            "wctomb workload imports the provider directly")
    rows = {}
    for name in ("fwscanf",):
        selected = [line.split() for line in symbols.stdout.splitlines()
                    if line.endswith(" " + name) and line.split()[0].endswith(":")]
        require(len(selected) == 1 and selected[0][3:7] == ["NOTYPE", "GLOBAL", "DEFAULT", "UND"],
                f"wctomb workload {name} import differs")
        calls = [line for line in relocations.stdout.splitlines()
                 if re.search(rf"\b{re.escape(name)}\s+-\s+4\b", line)]
        require(calls and all(re.search(r"\bR_X86_64_(PLT32|GOTPCREL)\b", line) for line in calls),
                f"wctomb workload {name} relocation differs")
        rows[name] = {"symbol": selected[0], "relocations": calls}
    require(not re.search(r"\bR_X86_64_(32|32S)\b", relocations.stdout),
            "wctomb workload retains an absolute 32-bit relocation")
    return rows


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
    require(result.returncode == 0, f"wctomb {label} failed: {result.stderr.decode(errors='replace')}")
    return {"argv": command, "stdout_sha256": digest(work / (label + ".stdout")),
            "stderr_sha256": digest(work / (label + ".stderr")), "status": result.returncode}


def collect(static_product: Path, dynamic_product: Path, output: Path) -> dict[str, Any]:
    output = output.absolute()
    require(output.is_relative_to(ROOT / ".work") and not output.exists()
            and output.parent.resolve() == output.parent, "wctomb output must be a fresh physical .work child")
    static_product = directory(static_product.absolute(), "wctomb static product")
    dynamic_product = directory(dynamic_product.absolute(), "wctomb dynamic product")
    source_before = digest(SOURCE)
    output.mkdir(mode=0o700)
    commands = {"compile": capture(compile_command(dynamic_product, output), output, "compile")}
    require(digest(SOURCE) == source_before, "wctomb source changed during compilation")
    rows = workload_rows(output / "workload.o")
    for mode in MODES:
        commands[mode] = capture(link_command(mode, static_product, dynamic_product, output), output, mode)
    report = {"schema": SCHEMA, "source_sha256": source_before,
              "source": inventory.collector_source_seal(),
              "static_product": str(static_product), "dynamic_product": str(dynamic_product),
              "dynamic_driver_sha256": digest(dynamic_product / "bin/crabc-cc-dynamic"),
              "static_driver_sha256": digest(static_product / "bin/crabc-cc"),
              "workload_sha256": digest(output / "workload.o"),
              "workload_rows": rows, "commands": commands,
              "links": {mode: product_evidence.validate_link(
                  static_product if mode.startswith("static") else dynamic_product,
                  output / "workload.o", output / mode, link_receipt(mode, output),
                  mode.removeprefix("dynamic-")) for mode in MODES}}
    require(digest(SOURCE) == source_before, "wctomb source changed during linking")
    (output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report


def validate_report(report_path: Path, *, static_product: Path, dynamic_product: Path) -> dict[str, Any]:
    report_path = regular(report_path.absolute(), "wctomb import report")
    require(report_path.name == "report.json", "wctomb report filename differs")
    work = directory(report_path.parent, "wctomb retained work")
    static_product = directory(static_product.absolute(), "wctomb static product")
    dynamic_product = directory(dynamic_product.absolute(), "wctomb dynamic product")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    require(type(report) is dict and set(report) == {
        "schema", "source_sha256", "source", "static_product", "dynamic_product",
        "dynamic_driver_sha256", "static_driver_sha256", "workload_sha256",
        "workload_rows", "commands", "links"}, "wctomb report shape differs")
    require(report["schema"] == SCHEMA and report["source_sha256"] == digest(SOURCE)
            and report["source"] == inventory.collector_source_seal()
            and report["static_product"] == str(static_product)
            and report["dynamic_product"] == str(dynamic_product)
            and report["dynamic_driver_sha256"] == digest(dynamic_product / "bin/crabc-cc-dynamic")
            and report["static_driver_sha256"] == digest(static_product / "bin/crabc-cc")
            and report["workload_sha256"] == digest(work / "workload.o")
            and report["workload_rows"] == workload_rows(work / "workload.o"),
            "wctomb source, products, or workload changed")
    require(set(report["commands"]) == {"compile", *MODES}
            and set(report["links"]) == set(MODES), "wctomb command or link roster differs")
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
            f"wctomb {label} transcript changed")
    for mode in MODES:
        expected = product_evidence.validate_link(
            static_product if mode.startswith("static") else dynamic_product,
            work / "workload.o", work / mode, link_receipt(mode, work),
            mode.removeprefix("dynamic-"))
        require(report["links"][mode] == expected, f"wctomb {mode} link changed")
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
    except (WctombImportError, OSError, ValueError, product_evidence.ProductEvidenceError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print("native ABI wctomb imports: PASS (source-bound owned links)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
