#!/usr/bin/env python3
"""Produce source-bound fixed-protocol-table evidence from three x86 products.

The selected x86 C ABI is a direct semantic port of musl 1.2.6
``src/network/proto.c``.  Its API is intentionally a fixed, process-global
36-record table; it does not select the separate Rust-facing ``/etc/protocols``
snapshot facade.  This producer translates one existing state-machine probe
with project headers, runs it through the pinned musl oracle, then links that
same object into three non-reused static/dynamic product pairs.  Each pair is
executed as static ET_EXEC, static PIE, dynamic PIE through the kernel and
direct interpreter, and dynamic non-PIE through both entries.

The result is a retained raw receipt below ``.work``.  The companion reader is
the public admission boundary: this script itself does not promote the
resolver family or x86 support.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "crabc.x86_64-owned-protocol-database-products/v1"
COMPONENT = "protocol-database-product"
ARMS = ("installed", "reproduction", "extracted")
ENTRY_MODES = (
    "static-et-exec",
    "static-pie",
    "dynamic-pie-kernel",
    "dynamic-pie-direct",
    "dynamic-non-pie-kernel",
    "dynamic-non-pie-direct",
)
PROVIDERS = (
    "endprotoent",
    "getprotobyname",
    "getprotobynumber",
    "getprotoent",
    "setprotoent",
)
MUSL_CC = Path("/usr/local/bin/crabc-x86_64-musl-gcc")
PROBE = Path("compat/x86_64/libc_protocol_database_probe.c")
RUST_PROVIDER = Path("libc/src/c_abi/x86_64/protocol_database.rs")
PROVIDER_CONTRACT = Path("compat/x86_64/protocol-database-provider.toml")
READER = Path("compat/x86_64/owned_protocol_database_receipt.py")
PRODUCT_FIXTURE = Path("compat/resolver-network/run_x86_64.py")
DYNAMIC_RECEIPT = Path("compat/x86_64/owned_dynamic_receipt.py")
POISON_PROTOCOLS = b"poison 253 deliberately-not-selected\n"
SOURCE_FILES = (
    Path(__file__).relative_to(ROOT), READER, PROBE, RUST_PROVIDER, PROVIDER_CONTRACT,
    PRODUCT_FIXTURE, DYNAMIC_RECEIPT,
)


class ProtocolDatabaseError(RuntimeError):
    """The fixed-table product receipt cannot be produced safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProtocolDatabaseError(message)


def _physical(path: Path, description: str, *, directory: bool = False) -> Path:
    try:
        value = Path(os.path.abspath(path))
        metadata = value.lstat()
        require(not value.is_symlink(), f"{description} is a symlink: {path}")
        require(stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode),
                f"{description} has the wrong type: {path}")
        current = Path(value.anchor)
        for part in value.parts[1:]:
            current /= part
            require(not current.is_symlink(), f"{description} traverses a symlink: {path}")
        return value
    except OSError as error:
        raise ProtocolDatabaseError(f"cannot read {description}: {path}") from error


def _below_work(path: Path, description: str, *, directory: bool) -> Path:
    value = _physical(path, description, directory=directory)
    require(value.is_relative_to(ROOT / ".work"), f"{description} must be below checkout .work")
    return value


def artifact(root: Path, path: Path) -> dict[str, object]:
    path = _physical(path, "receipt artifact")
    require(path.is_relative_to(root), f"receipt artifact escapes checkout: {path}")
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256(path.read_bytes()).hexdigest(),
        "byte_length": path.stat().st_size,
        "mode": stat.S_IMODE(path.stat().st_mode),
    }


def fixture_module() -> Any:
    source = _physical(ROOT / PRODUCT_FIXTURE, "resolver product fixture")
    name = f"owned_protocol_database_fixture_{sha256(str(ROOT).encode()).hexdigest()[:16]}"
    spec = importlib.util.spec_from_file_location(name, source)
    require(spec is not None and spec.loader is not None, "cannot load resolver product fixture")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        raise ProtocolDatabaseError(f"cannot load resolver product fixture: {error}") from error
    return module


def source_records(root: Path = ROOT) -> dict[str, dict[str, object]]:
    """Return the small source map that defines this fixed-table receipt."""

    return {path.as_posix(): artifact(root, root / path) for path in SOURCE_FILES}


def _run(arguments: Sequence[str | Path], *, cwd: Path, timeout: float, description: str) -> tuple[int, bytes, bytes]:
    try:
        result = subprocess.run([str(argument) for argument in arguments], cwd=cwd,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise ProtocolDatabaseError(f"{description} timed out") from error
    except OSError as error:
        raise ProtocolDatabaseError(f"cannot execute {description}: {error}") from error
    if result.returncode != 0:
        raise ProtocolDatabaseError(
            f"{description} failed ({result.returncode}): {result.stderr.decode(errors='replace')}"
        )
    return result.returncode, result.stdout, result.stderr


def _write_new(path: Path, value: bytes) -> None:
    require(not path.exists() and not path.is_symlink(), f"receipt output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def _write_json(path: Path, value: object) -> None:
    _write_new(path, json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode("utf-8") + b"\n")


def _readelf(path: Path, *, dynamic: bool, destination: Path, timeout: float) -> bytes:
    arguments = ("readelf", "--wide", "--dyn-syms" if dynamic else "--syms", str(path))
    _status, stdout, stderr = _run(arguments, cwd=ROOT, timeout=timeout, description="protocol provider symbol audit")
    require(not stderr, "protocol provider symbol audit wrote stderr")
    _write_new(destination, stdout)
    return stdout


def provider_rows(raw: bytes, description: str) -> dict[str, list[list[str]]]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ProtocolDatabaseError(f"{description} is not UTF-8") from error
    found: dict[str, list[list[str]]] = {name: [] for name in PROVIDERS}
    for line in lines:
        fields = line.split()
        if len(fields) == 8 and fields[7] in found:
            found[fields[7]].append(fields)
    for name, rows in found.items():
        require(rows, f"{description} lacks {name}")
        require(all(row[3:6] == ["FUNC", "GLOBAL", "DEFAULT"] and row[6] != "UND" for row in rows),
                f"{description} has an invalid provider binding for {name}")
    return found


def _oracle_object(work: Path, timeout: float) -> dict[str, object]:
    _physical(MUSL_CC, "pinned musl compiler")
    _status, stdout, _stderr = _run((MUSL_CC, "-print-file-name=libc.a"), cwd=ROOT, timeout=timeout,
                                    description="pinned musl archive query")
    archive = Path(stdout.decode("utf-8").strip())
    _physical(archive, "pinned musl archive")
    object_file = work / "oracle-proto.lo"
    _status, payload, _stderr = _run(("ar", "p", archive, "proto.lo"), cwd=ROOT, timeout=timeout,
                                     description="pinned musl proto.lo extraction")
    _write_new(object_file, payload)
    symbols = work / "oracle-proto.symbols"
    raw = _readelf(object_file, dynamic=False, destination=symbols, timeout=timeout)
    require(b"proto.c" in raw, "pinned musl proto object no longer identifies proto.c")
    provider_rows(raw, "pinned musl proto object")
    undefined = work / "oracle-proto.undefined"
    _status, raw_undefined, _stderr = _run(("nm", "--undefined-only", "--format=posix", object_file), cwd=ROOT,
                                            timeout=timeout, description="pinned musl proto import audit")
    _write_new(undefined, raw_undefined)
    imports = sorted(line.split()[0] for line in raw_undefined.decode("utf-8").splitlines() if line.split())
    require(imports == ["strcmp", "strlen"], "pinned musl proto object import surface differs")
    return {
        "archive": artifact(ROOT, archive) if archive.is_relative_to(ROOT) else {
            "path": str(archive), "sha256": sha256(archive.read_bytes()).hexdigest(),
            "byte_length": archive.stat().st_size, "mode": stat.S_IMODE(archive.stat().st_mode),
        },
        "object": artifact(ROOT, object_file),
        "symbols": artifact(ROOT, symbols),
        "undefined": artifact(ROOT, undefined),
    }


def _products(fixture: Any, values: Mapping[str, Path]) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    roots: list[Path] = []
    for arm in ARMS:
        static_root = _below_work(values[f"{arm}-static"], f"{arm} static product", directory=True)
        dynamic_root = _below_work(values[f"{arm}-dynamic"], f"{arm} dynamic product", directory=True)
        fixture.static_manifest(static_root)
        fixture.dynamic_manifest(dynamic_root)
        roots.extend((static_root, dynamic_root))
        result[arm] = {
            "static": {
                "path": static_root.relative_to(ROOT).as_posix(),
                "manifest": artifact(ROOT, static_root / "share/crabc/manifest.json"),
                "tree": fixture.receipt_tree_identity(static_root),
            },
            "dynamic": {
                "path": dynamic_root.relative_to(ROOT).as_posix(),
                "manifest": artifact(ROOT, dynamic_root / "share/crabc/manifest.json"),
                "tree": fixture.receipt_tree_identity(dynamic_root),
            },
        }
    require(len({(path.stat().st_dev, path.stat().st_ino) for path in roots}) == len(roots),
            "protocol products must use six distinct physical roots")
    for kind in ("static", "dynamic"):
        identities = [result[arm][kind]["tree"] for arm in ARMS]
        require(identities[0] == identities[1] == identities[2],
                f"installed, reproduction, and extracted {kind} products differ")
    return result


def _compile(work: Path, timeout: float) -> tuple[Path, dict[str, object]]:
    source = _physical(ROOT / PROBE, "fixed-table protocol probe")
    output = work / "workload.o"
    _run((MUSL_CC, "-std=c11", "-fno-builtin", "-fno-stack-protector", "-I", ROOT / "include",
          "-c", source, "-o", output), cwd=ROOT, timeout=timeout,
         description="fixed-table protocol workload compilation")
    return output, artifact(ROOT, output)


def _link_oracle(work: Path, object_file: Path, timeout: float) -> Path:
    output = work / "oracle"
    _run((MUSL_CC, "-static", "-fno-pie", "-no-pie", object_file, "-o", output), cwd=ROOT,
         timeout=timeout, description="pinned musl fixed-table oracle link")
    return output


def _link_candidates(fixture: Any, work: Path, roots: Mapping[str, Path], object_file: Path,
                     timeout: float) -> tuple[dict[str, dict[str, dict[str, object]]], dict[str, Path]]:
    artifacts: dict[str, dict[str, dict[str, object]]] = {}
    binaries: dict[str, Path] = {}
    for arm in ARMS:
        static_root, dynamic_root = roots[f"{arm}-static"], roots[f"{arm}-dynamic"]
        per_arm: dict[str, dict[str, object]] = {}
        static_driver = _physical(static_root / "bin/crabc-cc", f"{arm} static driver")
        for mode, option, elf_mode in (("static-et-exec", "--static-et-exec", "static"),
                                       ("static-pie", "--static-pie", "static-pie")):
            directory = work / "artifacts" / arm / mode
            directory.mkdir(parents=True)
            output, receipt = directory / "workload", directory / "link.receipt.json"
            _run((static_driver, option, "--link-receipt", receipt.name, object_file, "-o", output), cwd=directory,
                 timeout=timeout, description=f"{arm} {mode} link")
            per_arm[mode] = {
                "binary": artifact(ROOT, output),
                "receipt": fixture.static_receipt_audit(static_root, option, object_file, output, receipt),
                "elf": fixture.elf_audit(output, mode=elf_mode, dynamic=False),
            }
            binaries[f"{arm}-{mode}"] = output
        dynamic_driver = _physical(dynamic_root / "bin/crabc-cc-dynamic", f"{arm} dynamic driver")
        for mode, option, elf_mode in (("dynamic-pie", "--dynamic-pie", "dynamic-pie"),
                                       ("dynamic-non-pie", "--dynamic-non-pie", "dynamic-non-pie")):
            directory = work / "artifacts" / arm / mode
            directory.mkdir(parents=True)
            output = directory / "workload"
            _run((dynamic_driver, option, object_file, "-o", output), cwd=directory, timeout=timeout,
                 description=f"{arm} {mode} link")
            receipt = Path(str(output) + ".crabc-link.json")
            per_arm[mode] = {
                "binary": artifact(ROOT, output),
                "receipt": fixture.dynamic_receipt_audit(dynamic_root, option, object_file, output, receipt),
                "elf": fixture.elf_audit(output, mode=elf_mode, dynamic=True),
            }
            binaries[f"{arm}-{mode}"] = output
        artifacts[arm] = per_arm
    return artifacts, binaries


def _poison_protocols(root: Path) -> dict[str, object]:
    path = root / "etc/protocols"
    _write_new(path, POISON_PROTOCOLS)
    path.chmod(0o644)
    return artifact(ROOT, path)


def _chroots(fixture: Any, work: Path, roots: Mapping[str, Path], oracle: Path,
             binaries: Mapping[str, Path]) -> tuple[dict[str, dict[str, object]], dict[str, Path]]:
    layouts: dict[str, dict[str, object]] = {}
    execution_roots: dict[str, Path] = {}
    (work / "chroots").mkdir()
    root = work / "chroots" / "oracle"
    fixture.static_chroot(oracle, root)
    layouts["oracle"] = {"root": root.relative_to(ROOT).as_posix(), "protocols": _poison_protocols(root),
                          "tree": fixture.receipt_tree_identity(root)}
    execution_roots["oracle"] = root
    for arm in ARMS:
        for mode in ("static-et-exec", "static-pie"):
            label, root = f"{arm}-{mode}", work / "chroots" / f"{arm}-{mode}"
            fixture.static_chroot(binaries[label], root)
            layouts[label] = {"root": root.relative_to(ROOT).as_posix(), "protocols": _poison_protocols(root),
                              "tree": fixture.receipt_tree_identity(root)}
            execution_roots[label] = root
        for mode in ("dynamic-pie", "dynamic-non-pie"):
            label, root = f"{arm}-{mode}", work / "chroots" / f"{arm}-{mode}"
            fixture.dynamic_chroot(binaries[label], roots[f"{arm}-dynamic"], root)
            layouts[label] = {"root": root.relative_to(ROOT).as_posix(), "protocols": _poison_protocols(root),
                              "tree": fixture.receipt_tree_identity(root)}
            execution_roots[label] = root
    return layouts, execution_roots


def expected_executions() -> dict[str, tuple[str, list[str]]]:
    result = {"oracle": ("oracle", ["/workload"])}
    for arm in ARMS:
        result[f"{arm}-static-et-exec"] = (f"{arm}-static-et-exec", ["/workload"])
        result[f"{arm}-static-pie"] = (f"{arm}-static-pie", ["/workload"])
        result[f"{arm}-dynamic-pie-kernel"] = (f"{arm}-dynamic-pie", ["/workload"])
        result[f"{arm}-dynamic-pie-direct"] = (f"{arm}-dynamic-pie", ["/lib/ld-crabc-x86_64.so.1", "/workload"])
        result[f"{arm}-dynamic-non-pie-kernel"] = (f"{arm}-dynamic-non-pie", ["/workload"])
        result[f"{arm}-dynamic-non-pie-direct"] = (f"{arm}-dynamic-non-pie", ["/lib/ld-crabc-x86_64.so.1", "/workload"])
    return result


def _executions(fixture: Any, work: Path, roots: Mapping[str, Path], timeout: float) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for label, (root_label, argv) in expected_executions().items():
        status, stdout, stderr = fixture.run_chroot_raw(roots[root_label], argv, timeout)
        require(status == 0 and stdout == b"" and stderr == b"", f"{label} fixed-table probe differs")
        directory = work / "raw" / label
        directory.mkdir(parents=True)
        argv_path, status_path = directory / "argv.json", directory / "status"
        stdout_path, stderr_path = directory / "stdout", directory / "stderr"
        _write_new(argv_path, json.dumps(argv, separators=(",", ":")).encode("utf-8") + b"\n")
        _write_new(status_path, f"{status}\n".encode("ascii"))
        _write_new(stdout_path, stdout)
        _write_new(stderr_path, stderr)
        result[label] = {"root": root_label, "argv": artifact(ROOT, argv_path), "status": artifact(ROOT, status_path),
                         "stdout": artifact(ROOT, stdout_path), "stderr": artifact(ROOT, stderr_path)}
    return result


def _provider_audits(work: Path, oracle: Path, binaries: Mapping[str, Path], roots: Mapping[str, Path],
                     timeout: float) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    targets: dict[str, tuple[Path, bool]] = {"oracle": (oracle, False)}
    for arm in ARMS:
        targets[f"{arm}-static-et-exec"] = (binaries[f"{arm}-static-et-exec"], False)
        targets[f"{arm}-static-pie"] = (binaries[f"{arm}-static-pie"], False)
        targets[f"{arm}-dynamic-provider"] = (roots[f"{arm}-dynamic"] / "usr/lib/libc.so", True)
    for label, (binary, dynamic) in targets.items():
        raw = _readelf(binary, dynamic=dynamic, destination=work / "providers" / f"{label}.symbols", timeout=timeout)
        provider_rows(raw, label)
        result[label] = {"binary": artifact(ROOT, binary), "dynamic": dynamic,
                         "symbols": artifact(ROOT, work / "providers" / f"{label}.symbols")}
    return result


def _fresh_work(path: Path) -> Path:
    absolute = path if path.is_absolute() else ROOT / path
    absolute.mkdir(parents=True, exist_ok=True)
    work = _below_work(absolute, "protocol evidence work directory", directory=True)
    require(not any(work.iterdir()), "protocol evidence work directory must be empty")
    return work


def run(args: argparse.Namespace) -> Path:
    work = _fresh_work(args.work)
    fixture = fixture_module()
    roots = {
        f"{arm}-{kind}": getattr(args, f"{arm}_{kind}_sysroot")
        for arm in ARMS for kind in ("static", "dynamic")
    }
    source_before = source_records()
    products_before = _products(fixture, roots)
    oracle_object = _oracle_object(work, args.timeout)
    object_file, workload = _compile(work, args.timeout)
    oracle = _link_oracle(work, object_file, args.timeout)
    candidates, binaries = _link_candidates(fixture, work, roots, object_file, args.timeout)
    layouts, execution_roots = _chroots(fixture, work, roots, oracle, binaries)
    executions = _executions(fixture, work, execution_roots, args.timeout)
    providers = _provider_audits(work, oracle, binaries, roots, args.timeout)
    source_after, products_after = source_records(), _products(fixture, roots)
    require(source_before == source_after, "protocol receipt source changed during execution")
    require(products_before == products_after, "protocol receipt product changed during execution")
    report = {
        "schema": SCHEMA,
        "component": COMPONENT,
        "oracle": oracle_object,
        "source": {"before": source_before, "after": source_after},
        "products": {"before": products_before, "after": products_after},
        "workload": workload,
        "oracle_binary": artifact(ROOT, oracle),
        "candidates": candidates,
        "providers": providers,
        "isolation": layouts,
        "executions": executions,
        "entry_modes": list(ENTRY_MODES),
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
    }
    output = work / "owned-protocol-database-products.json"
    _write_json(output, report)
    output.chmod(0o444)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    for arm in ARMS:
        parser.add_argument(f"--{arm}-static-sysroot", required=True, type=Path)
        parser.add_argument(f"--{arm}-dynamic-sysroot", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if args.timeout <= 0 or args.timeout > 120:
        parser.error("--timeout must be > 0 and <= 120")
    try:
        output = run(args)
    except ProtocolDatabaseError as error:
        print(f"owned protocol database: ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"report": output.relative_to(ROOT).as_posix(), "passed": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
