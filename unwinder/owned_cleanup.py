#!/usr/bin/env python3
"""Run the full Rust cleanup fixture through supplied owned runtime products.

This is consumer-development evidence.  The selected provider is built beside
the receipt and passed directly to each link; it is deliberately *not*
installed into either supplied product.  Packaging that provider, a build-std
consumer, LTO, DSO discovery, and complete malformed-metadata behavior remain
separate requirements before any qualification or promotion claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Any

import cleanup
import build
import owned_rust_link


ROOT = Path(__file__).resolve().parent
CHECKOUT = ROOT.parent
WORK = CHECKOUT / ".work/x86_64/owned-rust-std-cleanup"
TARGET = "x86_64-unknown-linux-musl"
FIXTURE = ROOT / "fixtures/cleanup.rs"
SOURCE_INPUTS = (
    ROOT / "owned_cleanup.py", ROOT / "owned_rust_link.py", ROOT / "cleanup.py",
    ROOT / "build.py", FIXTURE,
)


class OwnedCleanupError(RuntimeError):
    """The supplied products or one recorded owned Rust consumer are unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise OwnedCleanupError(message)


def assert_nonpromoting(record: dict[str, Any], description: str) -> None:
    for field in ("qualified", "family_completion", "promotion_ready", "public_support"):
        require(record.get(field) is False, f"{description} changes non-promoting state: {field}")


def physical(path: Path, description: str, *, directory: bool = False, executable: bool = False) -> Path:
    if ".." in path.parts:
        raise OwnedCleanupError(f"{description} has parent traversal: {path}")
    candidate = Path(os.path.abspath(path))
    current = Path(candidate.anchor)
    try:
        for part in candidate.parts[1:]:
            current /= part
            if stat.S_ISLNK(current.lstat().st_mode):
                raise OwnedCleanupError(f"{description} traverses a symlink: {path}")
        metadata = candidate.lstat()
    except OSError as error:
        raise OwnedCleanupError(f"{description} is unreadable: {path}") from error
    kind = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if not kind:
        expected = "directory" if directory else "regular file"
        raise OwnedCleanupError(f"{description} is not a physical {expected}: {path}")
    if executable and not metadata.st_mode & 0o111:
        raise OwnedCleanupError(f"{description} is not executable: {path}")
    return candidate


def digest(path: Path) -> str:
    path = physical(path, "hashed artifact")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def json_object(path: Path, description: str) -> dict[str, Any]:
    path = physical(path, description)
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise OwnedCleanupError(f"{description} has a duplicate key: {key}")
            result[key] = value
        return result
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OwnedCleanupError(f"{description} is not valid JSON: {path}") from error
    if not isinstance(value, dict):
        raise OwnedCleanupError(f"{description} is not a JSON object: {path}")
    return value


def record_file(path: Path, description: str) -> dict[str, str]:
    return {"path": str(physical(path, description)), "sha256": digest(path)}


def work_child(path: Path, description: str, *, existing: bool = False) -> Path:
    candidate = Path(os.path.abspath(path))
    boundary = physical(CHECKOUT / ".work", "checkout work boundary", directory=True)
    if not candidate.is_relative_to(boundary) or candidate == boundary:
        raise OwnedCleanupError(f"{description} must remain below checkout .work: {path}")
    if existing:
        return physical(candidate, description, directory=True)
    parent = candidate.parent
    physical(parent, f"{description} parent", directory=True)
    if candidate.exists() or candidate.is_symlink():
        raise OwnedCleanupError(f"{description} must be fresh: {path}")
    return candidate


def product_snapshot(root: Path, mode: str) -> dict[str, Any]:
    """Use the existing product reader, then retain all of its physical state."""

    compat = CHECKOUT / "compat/x86_64"
    if str(compat) not in sys.path:
        sys.path.insert(0, str(compat))
    import owned_posix_product_evidence as product  # pylint: disable=import-outside-toplevel

    root = work_child(root, f"supplied owned {mode} product", existing=True)
    try:
        manifest, files = (
            product._validate_static_product(root) if mode == "static"
            else product._validate_dynamic_product(root)
        )
    except product.ProductEvidenceError as error:
        raise OwnedCleanupError(f"invalid supplied owned {mode} product: {error}") from error
    return {
        "root": str(root),
        "manifest": record_file(manifest, f"owned {mode} manifest"),
        "files": dict(files),
    }


def assert_same_product(snapshot: dict[str, Any], mode: str) -> None:
    current = product_snapshot(Path(str(snapshot["root"])), mode)
    if current != snapshot:
        raise OwnedCleanupError(f"supplied owned {mode} product changed during consumer collection")


def clean_environment() -> dict[str, str]:
    return {
        key: value for key, value in os.environ.items()
        if not key.startswith(("CARGO_", "RUSTFLAGS", "RUSTUP_TOOLCHAIN", "LD_"))
    }


def run_logged(command: list[str | Path], environment: dict[str, str], log: Path, description: str) -> str:
    if log.exists() or log.is_symlink():
        raise OwnedCleanupError(f"{description} log must be fresh: {log}")
    result = subprocess.run([str(item) for item in command], env=environment, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_text(result.stdout, encoding="utf-8")
    if result.returncode:
        raise OwnedCleanupError(f"{description} exited {result.returncode}; retained diagnostics: {log}")
    return result.stdout


def provider_snapshot(provider: Path, toolchain: str) -> dict[str, Any]:
    archive = physical(provider / "libcrabc-unwind.a", "selected provider archive")
    provenance_path = physical(provider / "provenance.json", "selected provider provenance")
    provenance = json_object(provenance_path, "selected provider provenance")
    require(provenance.get("schema") == 1 and provenance.get("target") == TARGET,
            "provider provenance has the wrong schema or target")
    require(provenance.get("qualified") is False and provenance.get("native_build_products") is False,
            "provider provenance has an unapproved qualification or product state")
    require(provenance.get("personality_owner") == "consumer Rust std",
            "provider provenance changes Rust personality ownership")
    require(provenance.get("archive") == {"name": archive.name, "sha256": digest(archive)},
            "provider provenance does not identify the selected archive")
    require(provenance.get("unwind_abi") == sorted(build.UNWIND_ABI),
            "provider provenance changes the selected unwind ABI")
    symbols = cleanup.archive_unwind_symbols(physical(provider / "defined-symbols.txt", "provider symbol inventory"))
    require(symbols == set(provenance["unwind_abi"]), "provider symbol inventory differs from provenance")
    require(toolchain == provenance.get("toolchain"), "consumer compiler differs from selected provider compiler")
    return {
        "archive": record_file(archive, "selected provider archive"),
        "provenance": record_file(provenance_path, "selected provider provenance"),
        "record": provenance,
        "defined_unwind_abi": sorted(symbols),
    }


def compile_mode(
    *, mode: str, root: Path, provider: dict[str, Any], channel: str, output: Path,
) -> dict[str, Any]:
    application = output / mode
    application.mkdir(mode=0o755)
    binary = application / "cleanup"
    stock_libdir = Path(run_logged(
        ["rustup", "run", channel, "rustc", "--target", TARGET, "--print", "target-libdir"],
        clean_environment(), application / "target-libdir.log", f"{mode} target-library discovery",
    ).strip())
    stock_libdir = physical(stock_libdir, f"{mode} stock target library directory", directory=True)
    environment = clean_environment()
    environment.update({
        "CRABC_OWNED_RUST_LINK_MODE": mode,
        "CRABC_OWNED_RUST_PRODUCT": str(root),
        "CRABC_OWNED_RUST_PROVIDER": str(provider["archive"]["path"]),
        "CRABC_OWNED_RUST_STOCK_LIBDIR": str(stock_libdir),
        "CRABC_OWNED_RUST_APPLICATION_ROOT": str(application),
        "CRABC_OWNED_RUST_CHANNEL": channel,
    })
    rust_arguments: list[str | Path] = [
        "rustup", "run", channel, "rustc", "--edition=2024", "--target", TARGET,
        "-C", "panic=unwind", "-C", "force-unwind-tables=yes",
        # The owned linker selects either static or dynamic crabc inputs.
        # Rust's musl defaults would inject its bundled CRT objects and native
        # unwind archive before that boundary, which must reject them.
        "-C", "link-self-contained=no", "-C", "target-feature=-crt-static",
        "-C", f"linker={ROOT / 'owned_rust_link.py'}", "-C", "link-arg=-Wl,--eh-frame-hdr",
    ]
    if mode == "static":
        rust_arguments.extend(("-C", "relocation-model=static"))
    rust_arguments.extend((FIXTURE, "-o", binary))
    run_logged(rust_arguments, environment, application / "compile.log", f"{mode} full Rust cleanup compile")
    binary = physical(binary, f"{mode} cleanup executable", executable=True)
    link_receipt_path = physical(Path(str(binary) + ".crabc-owned-rust-link.json"), f"{mode} link receipt")
    link_receipt = json_object(link_receipt_path, f"{mode} link receipt")
    require(link_receipt.get("mode") == mode and link_receipt.get("output") == record_file(binary, f"{mode} cleanup executable"),
            f"{mode} link receipt does not identify this executable")
    if link_receipt.get("provider_archive") != provider["archive"]:
        raise OwnedCleanupError(f"{mode} link receipt does not retain the selected provider archive")
    assert_nonpromoting(link_receipt, f"{mode} link receipt")
    trace = link_receipt.get("resolved_input_trace")
    command = link_receipt.get("command")
    require(isinstance(trace, str) and isinstance(command, list) and all(isinstance(item, str) for item in command),
            f"{mode} link receipt lacks exact command or trace")
    forbidden = ("libgcc", "libunwind", "-lgcc", "-lunwind", "-lc")
    require(not any(token in str(item) for item in command for token in forbidden),
            f"{mode} linker command admits an ambient native runtime request")
    require("libcrabc-unwind.a" in trace and not any(token in trace for token in ("libgcc", "libunwind")),
            f"{mode} link trace does not prove the selected provider without ambient unwind runtimes")
    return {
        "mode": mode,
        "stock_target_libdir": str(stock_libdir),
        "compile_log": record_file(application / "compile.log", f"{mode} compile log"),
        "target_libdir_log": record_file(application / "target-libdir.log", f"{mode} target library log"),
        "link_receipt": record_file(link_receipt_path, f"{mode} link receipt"),
        "link_command": command,
        "link_trace": trace,
        "binary": record_file(binary, f"{mode} cleanup executable"),
    }


def binary_unwind_symbols(binary: Path, environment: dict[str, str], log: Path, description: str) -> list[str]:
    symbols = run_logged(["nm", "--defined-only", binary], environment, log, description)
    return sorted({
        line.split()[-1] for line in symbols.splitlines()
        if len(line.split()) >= 3 and line.split()[-1].startswith("_Unwind_")
    })


def execute_mode(mode: str, consumer: dict[str, Any], dynamic_root: Path, output: Path) -> None:
    binary = Path(consumer["binary"]["path"])
    environment = clean_environment()
    if mode == "static":
        command: list[str | Path] = [binary]
    else:
        loader = physical(dynamic_root / "lib/ld-crabc-x86_64.so.1", "owned dynamic loader", executable=True)
        command = [loader, "--library-path", dynamic_root / "usr/lib", binary]
    result = subprocess.run([str(item) for item in command], env=environment, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output / "execution.stdout").write_text(result.stdout, encoding="utf-8")
    (output / "execution.stderr").write_text(result.stderr, encoding="utf-8")
    cleanup.assert_execution(result.returncode, result.stdout + result.stderr)
    consumer["execution"] = {
        "command": [str(item) for item in command],
        "status": result.returncode,
        "stdout": record_file(output / "execution.stdout", f"{mode} execution stdout"),
        "stderr": record_file(output / "execution.stderr", f"{mode} execution stderr"),
    }


def source_snapshot() -> list[dict[str, str]]:
    return [
        {"path": source.relative_to(CHECKOUT).as_posix(), "sha256": digest(source)}
        for source in SOURCE_INPUTS
    ]


def run(static_root: Path, dynamic_root: Path, output: Path | None = None) -> Path:
    require((platform.system(), platform.machine()) == ("Linux", "x86_64"), "native Linux/x86-64 required")
    # Retain failed executions through their logs, never checkout-root cores.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source_before = source_snapshot()
    static = product_snapshot(static_root, "static")
    dynamic = product_snapshot(dynamic_root, "dynamic")
    require(static["root"] != dynamic["root"], "static and dynamic product roots must be distinct")
    WORK.mkdir(parents=True, exist_ok=True)
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="run-", dir=WORK))
        output.chmod(0o755)
    else:
        output = work_child(output, "owned Rust cleanup output")
        output.mkdir(mode=0o755)
    output = physical(output, "owned Rust cleanup output", directory=True)
    channel = tomllib.loads((CHECKOUT / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
    environment = clean_environment()
    toolchain = run_logged(
        ["rustup", "run", channel, "rustc", "-Vv"], environment, output / "toolchain.log",
        "consumer compiler identity",
    )
    run_logged([sys.executable, "-B", ROOT / "build.py", "--output", output / "provider"], environment,
               output / "provider-build.log", "selected unwind provider build")
    provider = provider_snapshot(output / "provider", toolchain)
    consumers: dict[str, dict[str, Any]] = {}
    for mode, snapshot in (("static", static), ("dynamic", dynamic)):
        consumer = compile_mode(mode=mode, root=Path(snapshot["root"]), provider=provider, channel=channel, output=output)
        binary = Path(consumer["binary"]["path"])
        symbols = binary_unwind_symbols(binary, clean_environment(), output / mode / "symbols.log", f"{mode} cleanup symbol inventory")
        cleanup.assert_binary_unwind_symbols(set(symbols), set(provider["defined_unwind_abi"]))
        consumer["defined_unwind_abi"] = symbols
        consumer["symbols_log"] = record_file(output / mode / "symbols.log", f"{mode} cleanup symbol inventory")
        execute_mode(mode, consumer, Path(dynamic["root"]), output / mode)
        consumers[mode] = consumer
    assert_same_product(static, "static")
    assert_same_product(dynamic, "dynamic")
    require(provider_snapshot(output / "provider", toolchain) == provider, "selected provider changed during consumer collection")
    require(source_snapshot() == source_before, "owned Rust consumer source changed during collection")
    receipt = {
        "schema": 1,
        "scope": "owned static/dynamic stock Rust std cleanup consumer development",
        "source_inputs": source_before,
        "fixture": record_file(FIXTURE, "full Rust cleanup fixture"),
        "products": {"static": static, "dynamic": dynamic},
        "provider": provider,
        "consumers": consumers,
        "qualified": False,
        "family_completion": False,
        "promotion_ready": False,
        "public_support": False,
        "limitations": [
            "provider archive and provenance are separately supplied build evidence, not installed-product packaging",
            "this consumer uses stock Rust std; build-std/core matching remains unqualified",
            "consumer LTO, DSO discovery, and complete malformed unwind-metadata behavior remain unqualified",
        ],
    }
    receipt_path = output / "receipt.json"
    with receipt_path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static-sysroot", required=True, type=Path)
    parser.add_argument("--dynamic-sysroot", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="fresh checkout .work child for retained consumer evidence")
    arguments = parser.parse_args()
    try:
        print(run(arguments.static_sysroot, arguments.dynamic_sysroot, arguments.output))
    except (OwnedCleanupError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"crabc-owned-rust-std-cleanup: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
