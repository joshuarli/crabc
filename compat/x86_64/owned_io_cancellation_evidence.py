#!/usr/bin/env python3
"""Installed-header and specialized ELF evidence for the finite cancellation case.

The shell roster remains the fixture-selection owner. Each fixture has one
installed-driver object, independently checked sealed links, and unchanged
runtime witnesses. This module does not compile another application object or
implement cancellation, a linker, or a general header search policy.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

from owned_posix_product_evidence import ProductEvidenceError, validate_link

ROOT = Path(__file__).resolve().parents[2]
LOCAL_WITNESS = "compat/x86_64/owned_cancellation_proc_witness.h"
# The shell roster owns selection; this source-name contract owns the exact
# required and allowed local header closure. Absence matters for the two
# witness-free fixtures, so an unknown source must never inherit an allowance.
LOCAL_HEADERS_BY_SOURCE = {
    "owned_io_cancellation_probe.c": (LOCAL_WITNESS,),
    "owned_descriptor_cancellation_probe.c": (LOCAL_WITNESS,),
    "owned_socket_cancellation_probe.c": (LOCAL_WITNESS,),
    "owned_sleep_wait_cancellation_probe.c": (LOCAL_WITNESS,),
    "owned_open_lock_cancellation_probe.c": (LOCAL_WITNESS,),
    "owned_semaphore_wait_cancellation_probe.c": (),
    "owned_semaphore_cancellation_probe.c": (LOCAL_WITNESS,),
    "owned_signal_wait_cancellation_probe.c": (LOCAL_WITNESS,),
    "owned_entropy_cancellation_probe.c": (),
    "owned_sysv_message_cancellation_probe.c": (LOCAL_WITNESS,),
}
COMPILE_FLAGS = ["-std=c11", "-fno-builtin", "-fno-stack-protector"]
SCHEMA = "crabc.x86_64-owned-io-cancellation-compile/v1"


class EvidenceError(RuntimeError):
    """The cancellation fixture no longer matches its admitted evidence."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def regular(path: Path) -> Path:
    require(path.is_absolute() and path.resolve(strict=True) == path and path.is_file()
            and not path.is_symlink(), f"nonphysical or nonregular evidence file: {path}")
    return path


def digest(path: Path) -> str:
    return hashlib.sha256(regular(path).read_bytes()).hexdigest()


def write_new(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"), allow_nan=False)
        output.write("\n")


def read_json(path: Path) -> object:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result
    def invalid(value):
        raise EvidenceError(f"invalid JSON numeric constant: {value}")
    return json.loads(regular(path).read_text(), object_pairs_hook=unique, parse_constant=invalid)


def dependency_identity(root: Path, product: Path, source: Path, text: str,
                        required_headers: list[str]) -> dict[str, str]:
    """Admit installed headers, this source, and the one quoted witness header.

    A checkout include directory or another fixture-local header is never an
    implicit allowance. The eight proc-witness fixtures use the exact named
    local header; the other two need no local dependency beyond their source.
    """
    regular(source)
    require(source.parent == root / "compat/x86_64", "fixture source is outside its owner")
    require(source.name in LOCAL_HEADERS_BY_SOURCE, f"unknown cancellation fixture: {source.name}")
    require(":" in text, "compiler dependency output lacks its target")
    tokens = shlex.split(text.replace("\\\n", " ").split(":", 1)[1])
    require(bool(tokens), "compiler dependency output is empty")
    headers = product / "usr/include"
    require(headers.is_dir() and headers.resolve() == headers, "installed header root is not physical")
    required_local = {root / header for header in LOCAL_HEADERS_BY_SOURCE[source.name]}
    allowed_local = {source, *required_local}
    paths = set()
    for token in tokens:
        path = regular(Path(token))
        require(path in allowed_local or path.is_relative_to(headers), f"unowned header dependency: {path}")
        paths.add(path)
    require(source in paths, "compiler dependency output omitted the fixture source")
    for header in sorted(required_local):
        require(header in paths, f"required local header absent: {header}")
    for header in required_headers:
        relative = Path(header)
        require(not relative.is_absolute() and ".." not in relative.parts,
                "required header must name an installed relative header")
        require(headers / relative in paths, f"required installed header absent: {header}")
    return {str(path): digest(path) for path in sorted(paths)}


def installed_compiler(product: Path):
    helper = regular(product / "share/crabc/crabc_cc_static.py")
    spec = importlib.util.spec_from_file_location("io_cancellation_installed_compiler", helper)
    require(spec is not None and spec.loader is not None, "installed compiler policy is unreadable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def dependency_command(product: Path, source: Path, compiler: str) -> list[str]:
    # Repeat only preprocessing with the installed dynamic driver's exact
    # compiler and flag ordering. In particular, its initial strong stack
    # protector setting is overridden by this existing fixture's explicit
    # fno-stack-protector, and the selected mode remains PIE, not shared PIC.
    return [compiler, "-nostdinc", "-isystem", str(product / "usr/include"),
            "-ffreestanding", "-fno-builtin", "-fstack-protector-strong",
            *COMPILE_FLAGS, "-fPIE", "-M", "-H", str(source)]


def compile_identity(product: Path, source: Path, workload: Path, record: Path,
                     required_headers: list[str]) -> dict:
    policy = installed_compiler(product)
    compiler = policy.compiler()
    dependencies = record.with_suffix(".dependencies")
    trace = record.with_suffix(".headers")
    status = record.with_suffix(".exit-status")
    require(regular(status).read_bytes() == b"0\n", "dependency preprocessing failed")
    paths = dependency_identity(ROOT, product, source, regular(dependencies).read_text(), required_headers)
    files = {str(path): digest(path) for path in (
        product / "bin/crabc-cc-dynamic", product / "share/crabc/crabc_cc_static.py",
        product / "share/crabc/manifest.json", source, workload, dependencies, trace, status,
    )}
    return {"schema": SCHEMA, "product": str(product), "source": str(source), "object": str(workload),
            "driver_command": [str(product / "bin/crabc-cc-dynamic"), "--dynamic-pie",
                               *COMPILE_FLAGS, "-c", str(source), "-o", str(workload)],
            "dependency_command": dependency_command(product, source, compiler),
            "dependency_exit_status": 0, "required_headers": required_headers,
            "compiler": {"path": compiler, "sha256": digest(Path(compiler).resolve())},
            "files": files, "dependencies": paths}


def record_compile(product: Path, source: Path, workload: Path, record: Path,
                   required_headers: list[str]) -> None:
    policy = installed_compiler(product)
    source_before, object_before = digest(source), digest(workload)
    command = dependency_command(product, source, policy.compiler())
    with record.with_suffix(".dependencies").open("xb") as output, record.with_suffix(".headers").open("xb") as errors:
        result = subprocess.run(command, stdout=output, stderr=errors,
                                env=policy.clean_environment(), check=False)
    with record.with_suffix(".exit-status").open("x") as output:
        output.write(f"{result.returncode}\n")
    require(result.returncode == 0, "installed-header dependency preprocessing failed")
    require(digest(source) == source_before and digest(workload) == object_before,
            "fixture source or installed-driver object changed during dependency audit")
    write_new(record, compile_identity(product, source, workload, record, required_headers))


def verify_compile(product: Path, source: Path, workload: Path, record: Path,
                   required_headers: list[str]) -> None:
    observed = compile_identity(product, source, workload, record, required_headers)
    require(json.dumps(read_json(record), sort_keys=True, allow_nan=False) ==
            json.dumps(observed, sort_keys=True, allow_nan=False), "compile evidence identity changed")


def audit_static_views(linkage: str, views: dict[str, str]) -> None:
    """Preserve the legacy static cancellation gate's additional ELF judges.

    The common sealed-link validator supplies product/object/receipt binding.
    These checks retain this case's stronger static relocation and TLS limits.
    """
    require(linkage in {"static", "static-pie"}, "unknown static linkage")
    require(set(views) == {"header", "segments", "dynamic", "symbols", "relocations"},
            "incomplete static ELF inspection")
    header, segments, dynamic = views["header"], views["segments"], views["dynamic"]
    symbols, relocations = views["symbols"], views["relocations"]
    require("Advanced Micro Devices X86-64" in header, "static consumer machine drifted")
    kind = "EXEC" if linkage == "static" else "DYN"
    require(re.search(r"Type:\s+" + kind + r"\s", header) is not None, "static ELF type drifted")
    require("INTERP" not in segments and "Requesting program interpreter" not in segments,
            "static consumer selected an interpreter")
    require(re.search(r"NEEDED|JMPREL|PLTGOT", dynamic) is None, "static consumer selected dynamic runtime state")
    require(not any(len(fields := line.split()) >= 8 and fields[6] == "UND" for line in symbols.splitlines()),
            "static consumer retains an unresolved symbol")
    require(re.search(r"R_X86_64_(GLOB_DAT|JUMP_SLOT|TLSGD|TLSLD|TLSDESC|DTPMOD|DTPOFF)",
                      relocations + symbols) is None, "static consumer retains dynamic relocation or TLS")
    if linkage == "static-pie":
        require(re.search(r"^\s*PHDR\s", segments, re.MULTILINE) is not None, "static PIE lacks PT_PHDR")
        require(re.search(r"R_X86_64_GOTTPOFF|__tls_get_addr", relocations + symbols) is None,
                "static PIE retains unrelaxed initial TLS")
        require(all(kind == "R_X86_64_RELATIVE" for kind in re.findall(r"R_X86_64_[A-Z0-9_]+", relocations)),
                "static PIE retains a non-relative relocation")


def record_link(product: Path, workload: Path, consumer: Path, receipt: Path,
                linkage: str, identity_path: Path) -> None:
    identity = validate_link(product, workload, consumer, receipt, linkage)
    if linkage in {"static", "static-pie"}:
        views = {}
        for name, option in (("header", "-hW"), ("segments", "-lW"), ("dynamic", "-dW"),
                             ("symbols", "-sW"), ("relocations", "-rW")):
            views[name] = subprocess.check_output(["readelf", option, str(consumer)], text=True)
            with Path(str(consumer) + "." + name).open("x") as output:
                output.write(views[name])
        audit_static_views(linkage, views)
    write_new(identity_path, identity)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name in ("record-compile", "verify-compile"):
        command = subcommands.add_parser(name)
        for field in ("product", "source", "workload", "record"):
            command.add_argument(field, type=Path)
        command.add_argument("headers", nargs="+")
    link = subcommands.add_parser("record-link")
    for field in ("product", "workload", "consumer", "receipt"):
        link.add_argument(field, type=Path)
    link.add_argument("linkage", choices=("static", "static-pie", "pie", "non-pie"))
    link.add_argument("identity", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "record-link":
            record_link(args.product, args.workload, args.consumer, args.receipt, args.linkage, args.identity)
        else:
            function = record_compile if args.command == "record-compile" else verify_compile
            function(args.product, args.source, args.workload, args.record, args.headers)
    except (EvidenceError, ProductEvidenceError, OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"I/O cancellation evidence failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
